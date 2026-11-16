# Релизы на GitHub

Релизы публикуются в [Exelsioro/SelectiveVpn](https://github.com/Exelsioro/SelectiveVpn/releases). Для чистой установки и обновления используется один файл SelectiveVpn-Setup-win-x64.exe.

1. Для следующего релиза обновите Version в Directory.Build.props и закоммитьте изменения.
2. Из чистого рабочего дерева этого коммита выполните команду.

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\Build-Inno.ps1
   ```

3. Проверьте сборку, совпадение SHA-256, установку и обновление на тестовой машине. Публичный комплект содержит sing-box, OpenVPN Community Edition, Wintun и .NET. При обновлении он сохраняет ранее установленные настройки PlanetVPN и проверенный движок OpenVPN XOR.
4. Отправьте коммит в main и создайте черновик релиза с тегом v<Version>. Приложите только SelectiveVpn-Setup-win-x64.exe и SelectiveVpn-Setup-win-x64.exe.sha256 из artifacts/inno. В примечаниях дайте ссылки на исходники поставляемых версий sing-box и OpenVPN из THIRD-PARTY-NOTICES.txt.
5. Проверьте файлы черновика и опубликуйте его. [Страница последнего релиза](https://github.com/Exelsioro/SelectiveVpn/releases/latest) служит постоянной ссылкой для обновлений.

Флаг -PrivateBundle создаёт отдельный личный EXE с файлами провайдера и движком OpenVPN XOR. Храните такой комплект локально.
