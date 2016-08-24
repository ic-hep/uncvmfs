from distutils.core import setup, Extension

# The binary module for processing signatures.
siglib = Extension('CVMFSSig',
                    sources = ['CVMFSSig.c'],
                    libraries = ['crypto'])

# Install all the parts of unCVMFS, including the extension.
setup(name = 'uncvmfs',
      version = '0.6',
      description = 'A tool for unpacking CVMFS repos',
      scripts = ['uncvmfs', 'uncvmfs_tool'],
      py_modules = ['UNCVMFSLib'],
      ext_modules = [siglib])

