= 已分成 用戶空間 及 內核模組 兩 RPM 包，此頁已不適用，需要更新。 ＝

# 前言 #

本文將簡略解說如何以 RPM 方式安裝本軟體。

由於源碼生成內核模組，因此編譯輸出只能適用於特定的內核版本；

這表示每次內核版本更新的時候，源碼亦必須重新編譯。

暫時下載頁上的 RPM 檔，只基於套件包裝者在上傳時使用的內核版本；

建議按照以下步驟，自行編譯基於您系統內的內核版本的內核模組。

（以下步驟為 Fedora 12 或以上適用，並不保證於其他 Fedora 舊版本或分支能順利實行。）

# SRPM 安裝步驟 #

  1. 請確認系統已安裝最新套件（例如以 root 權限執行 yum）： kernel, kernel-headers, rpmdevtools, iptables-devel：  ` yum install kernel, kernel-headers, rpmdevtools, iptables-devel `
  1. 重新起動主機。
  1. 如果之前沒有做過套件包裝工作，請以正常用戶登入終端機執行，以生成 ~/rpmbuild/ 包裝套件用文件夾：  ` rpmdev-setuptree `
  1. 下傳 SRPM 檔到 ~/rpmbuild/：  ` rpm -Uvh [SRPM 檔的下載地址] `
  1. 進入 ~/rpmbuild/SPECS，執行 RPM 編譯：  ` cd ~/rpmbuild/SPECS; rpmbuild -ba west-chamber.spec `
  1. 耐心等候，編譯完成會生成適合您現在的內核版本的 RPM： ~/rpmbuild/SRPMS/[系統Arch］/west-chamber-版本號-發表號.rpm
  1. 以正常方式安裝 RPM，以 root 權限在終端機執行（如果屬內核版本更新的重新編譯，在安裝時要加入 --force 選項，忽略版本號的檢查。）：   ` rpm -Uvh ~/rpmbuild/SRPMS/[系統Arch］/west-chamber-版本號-發表號.rpm `
  1. 安裝完成，具體使用請查閱相關使用文檔。