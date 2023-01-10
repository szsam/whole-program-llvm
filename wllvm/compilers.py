from __future__ import absolute_import
from __future__ import print_function


import os
import sys
import tempfile
import hashlib
import subprocess

from shutil import copyfile
from .filetype import FileType
from .popenwrapper import Popen
from subprocess import check_output
from .arglistfilter import ArgumentListFilter

from .logconfig import logConfig

# Internal logger
_logger = logConfig(__name__)

def wcompile(mode):
    """ The workhorse, called from wllvm and wllvm++.
    """

    # Make sure we are not invoked from ccache
    parentCmd = subprocess.check_output(
            ['ps', '--no-header', '-o', 'comm', '-p', str(os.getppid())], text=True)
    if parentCmd.strip() == 'ccache':
        # The following error message is invisible in terminal
        # when ccache is using its preprocessor mode
        _logger.error('Should not be invoked from ccache')
        # When ccache detects an error in the preprocessor mode,
        # it will fall back to running the real compiler (wllvm)
        sys.exit(-1)

    rc = 1

    legible_argstring = ' '.join(list(sys.argv)[1:])

    # for diffing with gclang
    _logger.info('Entering CC [%s]', legible_argstring)

    try:
        cmd = list(sys.argv)
        cmd = cmd[1:]

        builder = getBuilder(cmd, mode)

        af = builder.getBitcodeArglistFilter()

        rc = buildObject(builder)

        # phase one compile failed. no point continuing
        if rc != 0:
            _logger.error('Failed to compile using given arguments: [%s]', legible_argstring)
            return rc

        # no need to generate bitcode (e.g. configure only, assembly, ....)
        (skipit, reason) = af.skipBitcodeGeneration()
        if skipit:
            _logger.debug('No work to do: %s', reason)
            _logger.debug(af.__dict__)
            return rc

        # phase two
        buildAndAttachBitcode(builder, af)

    except Exception as e:
        _logger.warning('%s: exception case: %s', mode, str(e))

    _logger.debug('Calling %s returned %d', list(sys.argv), rc)
    return rc




fullSelfPath = os.path.realpath(__file__)
prefix = os.path.dirname(fullSelfPath)
driverDir = prefix
asDir = os.path.abspath(os.path.join(driverDir, 'dragonegg_as'))


# Environmental variable for path to compiler tools (clang/llvm-link etc..)
llvmCompilerPathEnv = 'LLVM_COMPILER_PATH'

# Environmental variable for cross-compilation target.
binutilsTargetPrefixEnv = 'BINUTILS_TARGET_PREFIX'

# This is the ELF section name inserted into binaries
elfSectionName = '.llvm_bc'

# (Fix: 2016/02/16: __LLVM is now used by MacOS's ld so we changed the segment name to __WLLVM).
#
# These are the MACH_O segment and section name
# The SegmentName was __LLVM. Changed to __WLLVM to avoid clashing
# with a segment that ld now uses (since MacOS X 10.11.3?)
#
darwinSegmentName = '__WLLVM'
darwinSectionName = '__llvm_bc'


# Same as an ArgumentListFilter, but DO NOT change the name of the output filename when
# building the bitcode file so that we don't clobber the object file.
class ClangBitcodeArgumentListFilter(ArgumentListFilter):
    def __init__(self, arglist):
        localCallbacks = {'-o' : (1, ClangBitcodeArgumentListFilter.outputFileCallback)}
        #super(ClangBitcodeArgumentListFilter, self).__init__(arglist, exactMatches=localCallbacks)
        super().__init__(arglist, exactMatches=localCallbacks)

    def outputFileCallback(self, flag, filename):
        self.outputFilename = filename


def getHashedPathName(path):
    return hashlib.sha256(path.encode('utf-8')).hexdigest() if path else None


def attachBitcodePathToObject(bcPath, outFileName):
    # Don't try to attach a bitcode path to a binary.  Unfortunately
    # that won't work.
    (_, ext) = os.path.splitext(outFileName)
    _logger.debug('attachBitcodePathToObject: %s  ===> %s [ext = %s]', bcPath, outFileName, ext)

    #iam: just object files, right?
    fileType = FileType.getFileType(outFileName)
    if fileType not in (FileType.MACH_OBJECT, FileType.ELF_OBJECT):
    #if fileType not in (FileType.MACH_OBJECT, FileType.MACH_SHARED, FileType.ELF_OBJECT, FileType.ELF_SHARED):
        _logger.warning('Cannot attach bitcode path to "%s of type %s"', outFileName, FileType.getFileTypeString(fileType))
        return

    #iam: this also looks very dodgey; we need a more reliable way to do this:
    #if ext not in ('.o', '.lo', '.os', '.So', '.po'):
    #    _logger.warning('Cannot attach bitcode path to "%s of type %s"', outFileName, FileType.getReadableFileType(outFileName))
    #    return

    # Now just build a temporary text file with the full path to the
    # bitcode file that we'll write into the object file.
    f = tempfile.NamedTemporaryFile(mode='w+b', delete=False)
    absBcPath = os.path.abspath(bcPath)
    f.write(absBcPath.encode())
    f.write('\n'.encode())
    _logger.debug('Wrote "%s" to file "%s"', absBcPath, f.name)

    # Ensure buffers are flushed so that objcopy doesn't read an empty
    # file
    f.flush()
    os.fsync(f.fileno())
    f.close()

    binUtilsTargetPrefix = os.getenv(binutilsTargetPrefixEnv)

    # Now write our bitcode section
    if sys.platform.startswith('darwin'):
        objcopyBin = f'{binUtilsTargetPrefix}-{"ld"}' if binUtilsTargetPrefix else 'ld'
        objcopyCmd = [objcopyBin, '-r', '-keep_private_externs', outFileName, '-sectcreate', darwinSegmentName, darwinSectionName, f.name, '-o', outFileName]
    else:
        objcopyBin = f'{binUtilsTargetPrefix}-{"objcopy"}' if binUtilsTargetPrefix else 'objcopy'
        objcopyCmd = [objcopyBin, '--add-section', f'{elfSectionName}={f.name}', outFileName]
    orc = 0

    # loicg: If the environment variable WLLVM_BC_STORE is set, copy the bitcode
    # file to that location, using a hash of the original bitcode path as a name
    storeEnv = os.getenv('WLLVM_BC_STORE')
    if storeEnv:
        hashName = getHashedPathName(absBcPath)
        copyfile(absBcPath, os.path.join(storeEnv, hashName))

    try:
        if os.path.getsize(outFileName) > 0:
            objProc = Popen(objcopyCmd)
            orc = objProc.wait()
    except OSError:
        # configure loves to immediately delete things, causing issues for
        # us here.  Just ignore it
        os.remove(f.name)
        sys.exit(0)

    os.remove(f.name)

    if orc != 0:
        _logger.error('objcopy failed with %s', orc)
        sys.exit(-1)

class BuilderBase:
    def __init__(self, cmd, mode, prefixPath=None):
        self.af = None     #memoize the arglist filter
        self.cmd = cmd
        self.mode = mode

        # Used as prefix path for compiler
        if prefixPath:
            self.prefixPath = prefixPath
            # Ensure prefixPath has trailing slash
            if self.prefixPath[-1] != os.path.sep:
                self.prefixPath = self.prefixPath + os.path.sep
            # Check prefix path exists
            if not os.path.exists(self.prefixPath):
                errorMsg = 'Path to compiler "%s" does not exist'
                _logger.error(errorMsg, self.prefixPath)
                raise Exception(errorMsg)

        else:
            self.prefixPath = ''

    def getCommand(self):
        if self.af is not None:
            # need to remove things like "-dead_strip"
            forbidden = self.af.forbiddenArgs
            if forbidden:
                for baddy in forbidden:
                    self.cmd.remove(baddy)
        return self.cmd


class ClangBuilder(BuilderBase):

    def getBitcodeGenerationFlags(self):
        # iam: If the environment variable LLVM_BITCODE_GENERATION_FLAGS is set we will add them to the
        # bitcode generation step
        bitcodeFLAGS  = os.getenv('LLVM_BITCODE_GENERATION_FLAGS')
        if bitcodeFLAGS:
            return bitcodeFLAGS.split()
        return []

    def getBitcodeCompiler(self):
        cc = self.getCompiler()
        return cc + ['-emit-llvm'] + self.getBitcodeGenerationFlags()

    def getCompiler(self):
        if self.mode == "wllvm++":
            env, prog = 'LLVM_CXX_NAME', 'clang++'
        elif self.mode == "wllvm":
            env, prog = 'LLVM_CC_NAME', 'clang'
        elif self.mode == "wfortran":
            env, prog = 'LLVM_F77_NAME', 'flang'
        else:
            raise Exception(f'Unknown mode {self.mode}')
        return [f'{self.prefixPath}{os.getenv(env) or prog}']

    def getBitcodeArglistFilter(self):
        if self.af is None:
            self.af = ClangBitcodeArgumentListFilter(self.cmd)
        return self.af

class DragoneggBuilder(BuilderBase):
    def getBitcodeCompiler(self):
        pth = os.getenv('LLVM_DRAGONEGG_PLUGIN')
        cc = self.getCompiler()
        # We use '-B' to tell gcc where to look for an assembler.
        # When we build LLVM bitcode we do not want to use the GNU assembler,
        # instead we want gcc to use our own assembler (see as.py).
        cmd = cc + ['-B', asDir, f'-fplugin={pth}', '-fplugin-arg-dragonegg-emit-ir']
        _logger.debug(cmd)
        return cmd

    def getCompiler(self):
        pfx = ''
        if os.getenv('LLVM_GCC_PREFIX') is not None:
            pfx = os.getenv('LLVM_GCC_PREFIX')

        if self.mode == "wllvm++":
            mode = 'g++'
        elif self.mode == "wllvm":
            mode = 'gcc'
        elif self.mode == "wfortran":
            mode = 'gfortran'
        else:
            raise Exception(f'Unknown mode {self.mode}')
        return [f'{self.prefixPath}{pfx}{mode}']

    def getBitcodeArglistFilter(self):
        if self.af is None:
            self.af = ArgumentListFilter(self.cmd)
        return self.af

class HybridBuilder(ClangBuilder):

    def __init__(self, cmd, mode, prefixPath=None):
        super().__init__(cmd, mode, prefixPath)
        gccPathEnv = 'GCC_PATH' # Optional
        gccCrossCompilePfxEnv = 'GCC_CROSS_COMPILE_PREFIX' # Optional

        gccPath = ''
        if os.getenv(gccPathEnv) is not None:
            gccPath = os.getenv(gccPathEnv)
            if gccPath[-1] != os.path.sep:
                gccPath = gccPath + os.path.sep
            if not os.path.exists(gccPath):
                errorMsg = 'Path to GCC compiler "%s" does not exist'
                _logger.error(errorMsg, gccPath)
                raise Exception(errorMsg)

        gccCrossCompilePfx = ''
        if os.getenv(gccCrossCompilePfxEnv) is not None:
            gccCrossCompilePfx = os.getenv(gccCrossCompilePfxEnv)

        if self.mode == "wllvm++":
            mode = 'g++'
        elif self.mode == "wllvm":
            mode = 'gcc'
        #elif self.mode == "wfortran":
        #    mode = 'gfortran'
        else:
            raise Exception(f'Unknown mode {self.mode}')
        self._compiler = f'{gccPath}{gccCrossCompilePfx}{mode}'
        _logger.debug(self._compiler)

        if os.getenv(binutilsTargetPrefixEnv) is None:
            # remove trailing '-'
            os.environ[binutilsTargetPrefixEnv] = f'{gccPath}{gccCrossCompilePfx}'[:-1]

        # Backward-compatibility only
        if (os.getenv(gccPathEnv) is None and os.getenv(gccCrossCompilePfxEnv) is None and
                os.getenv(binutilsTargetPrefixEnv) is not None):
            self._compiler = f'{os.getenv(binutilsTargetPrefixEnv)}-{mode}'
            _logger.debug(self._compiler)

    def _getIncludeSearchPaths(self):
        if self.mode == "wllvm":
            lang = 'c'
        elif self.mode == "wllvm++":
            lang = 'c++'
        else:
            raise Exception(f'Unknown mode {self.mode}')
        outs = check_output(
            f"{self._compiler} -E -x {lang} - -v < /dev/null 2>&1 "
            "| sed -n '/#include <...> search starts here:/, /End of search list./p' "
            "| sed '1d;$d'", shell=True, text=True)
        includeSearchPaths = []
        for path in outs.splitlines():
            includeSearchPaths.append("-idirafter")
            includeSearchPaths.append(path.strip())
        includeSearchPaths.append('-nostdinc')
        return includeSearchPaths

    def getBitcodeGenerationFlags(self):
        flags = super().getBitcodeGenerationFlags()
        flags.extend(self._getIncludeSearchPaths())
        if 'arm' in self._compiler:
            targetTriple = 'arm-none-eabi'
        elif 'i386-pc' in self._compiler:
            targetTriple = 'i386-pc-none-gnu'
        else:
            targetTriple = None
        if targetTriple:
            flags.extend(['-target', targetTriple])
        flags.append('-fno-inline')
        flags.append('-g')
        return flags

    def getBitcodeCompiler(self):
        #cc = self.getCompiler()
        cc = super().getCompiler()
        return cc + ['-emit-llvm'] + self.getBitcodeGenerationFlags()

    def getCompiler(self):
        return [self._compiler]


def getBuilder(cmd, mode):
    compilerEnv = 'LLVM_COMPILER'
    cstring = os.getenv(compilerEnv)
    pathPrefix = os.getenv(llvmCompilerPathEnv) # Optional

    _logger.debug('WLLVM compiler using %s', cstring)
    if pathPrefix:
        _logger.debug('WLLVM compiler path prefix "%s"', pathPrefix)

    if cstring == 'clang':
        return ClangBuilder(cmd, mode, pathPrefix)
    if cstring == 'dragonegg':
        return DragoneggBuilder(cmd, mode, pathPrefix)
    if cstring == 'hybrid':
        return HybridBuilder(cmd, mode, pathPrefix)
    if cstring is None:
        errorMsg = ' No compiler set. Please set environment variable %s'
        _logger.critical(errorMsg, compilerEnv)
        raise Exception(errorMsg)
    errorMsg = '%s = %s : Invalid compiler type'
    _logger.critical(errorMsg, compilerEnv, str(cstring))
    raise Exception(errorMsg)

def buildObject(builder):
    objCompiler = builder.getCompiler()
    objCompiler.extend(builder.getCommand())
    _logger.debug('buildObject %s', objCompiler)
    proc = Popen(objCompiler)
    rc = proc.wait()
    _logger.debug('buildObject rc = %d', rc)
    return rc


# This command does not have the executable with it
def buildAndAttachBitcode(builder, af):

    #iam: when we have multiple input files we'll have to keep track of their object files.
    newObjectFiles = []

    hidden = not af.isCompileOnly

    if  len(af.inputFiles) == 1 and af.isCompileOnly:
        _logger.debug('Compile only case: %s', af.inputFiles[0])
        # iam:
        # we could have
        # "... -c -o foo.o" or even "... -c -o foo.So" which is OK, but we could also have
        # "... -c -o crazy-assed.objectfile" which we wouldn't get right (yet)
        # so we need to be careful with the objFile and bcFile
        # maybe python-magic is in our future ...
        srcFile = af.inputFiles[0]
        (objFile, bcFile) = af.getArtifactNames(srcFile, hidden)
        if af.outputFilename is not None:
            objFile = af.outputFilename
            bcFile = af.getBitcodeFileName()
        buildBitcodeFile(builder, srcFile, bcFile)
        attachBitcodePathToObject(bcFile, objFile)

    else:

        for srcFile in af.inputFiles:
            _logger.debug('Not compile only case: %s', srcFile)
            (objFile, bcFile) = af.getArtifactNames(srcFile, hidden)
            if hidden:
                buildObjectFile(builder, srcFile, objFile)
                newObjectFiles.append(objFile)

            if srcFile.endswith('.bc'):
                _logger.debug('attaching %s to %s', srcFile, objFile)
                attachBitcodePathToObject(srcFile, objFile)
            else:
                _logger.debug('building and attaching %s to %s', bcFile, objFile)
                buildBitcodeFile(builder, srcFile, bcFile)
                attachBitcodePathToObject(bcFile, objFile)


    if not af.isCompileOnly:
        linkFiles(builder, newObjectFiles)

    sys.exit(0)

def linkFiles(builder, objectFiles):
    af = builder.getBitcodeArglistFilter()
    outputFile = af.getOutputFilename()
    cc = builder.getCompiler()
    cc.extend(objectFiles)
    cc.extend(af.objectFiles)
    cc.extend(af.linkArgs)
    cc.extend(['-o', outputFile])
    _logger.debug('linkFiles %s', cc)
    proc = Popen(cc)
    rc = proc.wait()
    if rc != 0:
        _logger.warning('Failed to link "%s"', str(cc))
        sys.exit(rc)


def buildBitcodeFile(builder, srcFile, bcFile):
    af = builder.getBitcodeArglistFilter()
    bcc = builder.getBitcodeCompiler()
    bcc.extend(af.compileArgs)
    bcc.extend(['-c', srcFile])
    bcc.extend(['-o', bcFile])
    _logger.debug('buildBitcodeFile: %s', bcc)
    proc = Popen(bcc)
    rc = proc.wait()
    if rc != 0:
        _logger.warning('Failed to generate bitcode "%s" for "%s"', bcFile, srcFile)
        sys.exit(rc)

def buildObjectFile(builder, srcFile, objFile):
    af = builder.getBitcodeArglistFilter()
    cc = builder.getCompiler()
    cc.extend(af.compileArgs)
    cc.append(srcFile)
    cc.extend(['-c', '-o', objFile])
    _logger.debug('buildObjectFile: %s', cc)
    proc = Popen(cc)
    rc = proc.wait()
    if rc != 0:
        _logger.warning('Failed to generate object "%s" for "%s"', objFile, srcFile)
        sys.exit(rc)

# bd & iam:
#
# case 1 (compileOnly):
#
# if the -c flag exists then so do all the .o files, and we need to
# locate them and produce and embed the bit code.
#
# locating them is easy:
#   either the .o is in the cmdline and we are in the simple case,
#   or else it was generated according to getObjectFilename
#
# we then produce and attach bitcode for each inputFile in the cmdline
#
#
# case 2 (compile and link)
#
#  af.inputFiles is not empty, and compileOnly is false.
#  in this case the .o's may not exist, we must regenerate
#  them in any case.
#
#
# case 3 (link only)
#
# in this case af.inputFiles is empty and we are done
#
#
