using System;
using System.IO;
using System.Text.Json;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

class Config
{
    public string scanEngine1 { get; set; } = "";
    public string scanEngine2 { get; set; } = "";
}

class SystemWideMonitor
{
    private static readonly BlockingCollection<(string filePath, int parentPID)> eventQueue =
        new(new ConcurrentQueue<(string, int)>());
    private static readonly string quarantinePath = @"C:\ProgramData\SilentGuard\Quarantine";
    private static readonly string logDirectory = @"C:\ProgramData\SilentGuard\log";
    private static readonly CancellationTokenSource cts = new();

    private static string scanEngine1Path = "";
    private static string scanEngine2Path = "";

    private static readonly string[] dangerousExtensions = new[]
    {
        ".exe", ".dll", ".sys", ".bat", ".cmd", "txt", ".ps1",
        ".vbs", ".js", ".py", ".wsf", ".msi", ".scr", ".com"
    };

    private static readonly ConcurrentDictionary<string, DateTime> recentFiles = new();

    static async Task Main(string[] args)
    {
        Console.WriteLine("OS 全体の監視を開始します。Ctrl+C で終了してください。");

        LoadConfig();

        Directory.CreateDirectory(quarantinePath);
        Directory.CreateDirectory(logDirectory);

        _ = Task.Run(() => StartETWMonitoring(cts.Token));
        _ = Task.Run(() => StartFileSystemWatcher(cts.Token));
        _ = Task.Run(() => ProcessEvents(cts.Token));

        Console.CancelKeyPress += (sender, e) =>
        {
            Console.WriteLine("終了処理中...");
            cts.Cancel();
            e.Cancel = true;
        };

        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token);
        }
        catch (TaskCanceledException) { }

        Console.WriteLine("終了しました。");
    }

    private static void LoadConfig()
    {
        try
        {
            string configText = File.ReadAllText("config.json");
            var config = JsonSerializer.Deserialize<Config>(configText);
            if (config != null)
            {
                scanEngine1Path = config.scanEngine1;
                scanEngine2Path = config.scanEngine2;
                Console.WriteLine($"[設定] Engine1: {scanEngine1Path}");
                Console.WriteLine($"[設定] Engine2: {scanEngine2Path}");
            }
            else
            {
                Console.WriteLine("[警告] config.json の内容が不正です。");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[警告] config.json 読み込み失敗: {ex.Message}");
        }
    }

    private static void StartETWMonitoring(CancellationToken token)
    {
        using var session = new TraceEventSession("StealthGuardSession") { StopOnDispose = true };

        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.FileIOInit
        );

        session.Source.Kernel.FileIOCreate += data =>
        {
            if (data == null) return;
            if (((int)data.CreateOptions & 0x00000003) == 0x00000003)
                return;

            string? filePath = data.FileName;
            if (!string.IsNullOrEmpty(filePath) && IsDangerousFile(filePath))
            {
                Console.WriteLine($"[作成検知: ETW] {filePath}");
                eventQueue.Add((filePath, data.ProcessID));
            }
        };

        session.Source.Kernel.FileIOWrite += data =>
        {
            if (data == null) return;

            string? filePath = data.FileName;
            if (!string.IsNullOrEmpty(filePath) && IsDangerousFile(filePath))
            {
                Console.WriteLine($"[書き込み検知: ETW] {filePath}");
                eventQueue.Add((filePath, data.ProcessID));
            }
        };

        Console.WriteLine("ETWセッション開始。");
        session.Source.Process();
    }

    private static async Task StartFileSystemWatcher(CancellationToken token)
    {
        var watcher = new FileSystemWatcher
        {
            Path = @"C:\",
            Filter = "*.*",
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
        };

        watcher.Created += (sender, e) => HandleFileSystemEvent(e.FullPath);
        watcher.Changed += (sender, e) => HandleFileSystemEvent(e.FullPath);

        watcher.EnableRaisingEvents = true;

        Console.WriteLine("FileSystemWatcher開始。");

        try
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(1000, token);
            }
        }
        catch (TaskCanceledException) { }
    }

    private static void HandleFileSystemEvent(string filePath)
    {
        if (!IsDangerousFile(filePath)) return;

        var now = DateTime.Now;
        if (recentFiles.TryGetValue(filePath, out var lastTime))
        {
            if ((now - lastTime).TotalMilliseconds < 1000) return; // 1秒以内の重複は無視
        }

        recentFiles[filePath] = now;
        Console.WriteLine($"[FSW検知] {filePath}");
        eventQueue.Add((filePath, 0));
    }

    private static bool IsDangerousFile(string filePath)
    {
        try
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            return dangerousExtensions.Contains(ext);
        }
        catch
        {
            return false;
        }
    }

    private static async Task ProcessEvents(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            if (eventQueue.TryTake(out var evt, 500))
            {
                await ScanAndProcess(evt.filePath, evt.parentPID);
            }
        }
    }

    private static async Task ScanAndProcess(string filePath, int parentPID)
    {
        try
        {
            if (!File.Exists(scanEngine1Path))
            {
                await LogFileEvent(filePath, threatFound: false, action: "No Engine1");
                return;
            }

            bool threatFound = await ScanWithEngine(scanEngine1Path, filePath);
            string actionTaken = "None";
            if (threatFound)
            {
                TerminateProcessesUsingFile(filePath);

                string quarantineFilePath = Path.Combine(quarantinePath, Path.GetFileName(filePath));
                try
                {
                    File.Move(filePath, quarantineFilePath);
                    Console.WriteLine($"[隔離] {filePath} を {quarantineFilePath} へ移動しました。");
                    actionTaken = "Quarantine";
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[エラー] ファイル隔離中にエラー: {ex.Message}");
                    actionTaken = "隔離失敗";
                    await LogFileEvent(filePath, threatFound, actionTaken);
                    return;
                }

                if (File.Exists(scanEngine2Path) && await ScanWithEngine(scanEngine2Path, quarantineFilePath))
                {
                    try
                    {
                        File.Delete(quarantineFilePath);
                        Console.WriteLine($"[削除] {quarantineFilePath} を削除しました。");
                        actionTaken = "Quarantine->Deleted";
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[エラー] ファイル削除中にエラー: {ex.Message}");
                        actionTaken = "削除失敗";
                    }
                }
            }
            else
            {
                actionTaken = "Scanned OK";
            }

            await LogFileEvent(filePath, threatFound, actionTaken);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"スキャン処理中にエラー: {ex.Message}");
        }
    }

    private static async Task<bool> ScanWithEngine(string enginePath, string filePath)
    {
        try
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = enginePath,
                Arguments = $"-Scan -ScanType 3 -File \"{filePath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var process = Process.Start(processInfo))
            {
                if (process == null)
                    return false;

                string output = await process.StandardOutput.ReadToEndAsync();
                process.WaitForExit();

                return (output.Contains("Threat found", StringComparison.OrdinalIgnoreCase)
                    || output.Contains("脅威が見つかりました", StringComparison.OrdinalIgnoreCase));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"スキャンエンジン実行時にエラー: {ex.Message}");
            return false;
        }
    }

    private static void TerminateProcessesUsingFile(string filePath)
    {
        try
        {
            var processes = Process.GetProcesses()
                .Where(p =>
                {
                    try
                    {
                        return p.MainModule?.FileName?.Equals(filePath, StringComparison.OrdinalIgnoreCase) == true;
                    }
                    catch
                    {
                        return false;
                    }
                })
                .ToList();

            foreach (var process in processes)
            {
                try
                {
                    process.Kill();
                    process.WaitForExit();
                    Console.WriteLine($"[終了] プロセス {process.ProcessName} (PID: {process.Id}) を強制終了しました。");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[エラー] プロセス {process.ProcessName} を終了できませんでした: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[エラー] プロセス検索中にエラー: {ex.Message}");
        }
    }

    private static async Task LogFileEvent(string filePath, bool threatFound, string action)
    {
        string sha256 = ComputeSHA256(filePath) ?? "不明";
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        string logRecord = $"{timestamp} | {filePath} | SHA256={sha256} | Threat={(threatFound ? "有" : "無")} | Action={action}";

        string logFileName = $"{DateTime.Now:yyyyMMdd_HH}.log";
        string logFilePath = Path.Combine(logDirectory, logFileName);

        try
        {
            await File.AppendAllTextAsync(logFilePath, logRecord + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[エラー] ログファイル出力中にエラー: {ex.Message}");
        }
    }

    private static string? ComputeSHA256(string filePath)
    {
        try
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }
}
