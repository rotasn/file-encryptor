import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Explicitly collect PyQt5 modules
pyqt5_hiddenimports = collect_submodules('PyQt5')
pyqt5_data = collect_data_files('PyQt5')

a = Analysis(
    ['file_encryptor.py'],
    pathex=[],
    binaries=[],
    datas=pyqt5_data,  # Include PyQt5 data files
    hiddenimports=pyqt5_hiddenimports,  # Include PyQt5 modules
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='FileEncryptor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to True temporarily for debugging
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='encryptorpython.ico',
)