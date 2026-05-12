# Interactive 2FA key picker (default mode).
# On WSL without xclip, fall back to:
#   2fa | clip.exe
function mfa
  2fa $argv
end
