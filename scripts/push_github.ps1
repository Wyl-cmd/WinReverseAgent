# 一键推送（GitHub SSH over 443，适配受限网络）
# 前置：将项目根 cat ~/.ssh/id_rsa.pub 的公钥加入 GitHub：
#   GitHub -> Settings -> SSH and GPG keys -> New SSH key
& git push -u origin main
Write-Host "推送完成" -ForegroundColor Green
