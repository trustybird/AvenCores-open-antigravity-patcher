from patcher.vscode.discovery import (
    find_extension_dir,
    find_extension_js,
    resolve_extension_path,
    find_gemini_antigravity_binary,
    describe_gemini_binary_path,
)
from patcher.vscode.patcher import (
    is_already_patched,
    do_patch_vscode,
    do_restore_vscode,
)
