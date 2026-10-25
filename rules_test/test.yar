rule Test_Downloader
{
    strings:
        $a = "URLDownloadToFileA"
    condition:
        $a
}
