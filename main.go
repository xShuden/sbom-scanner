package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

const helpText = `SBOM Scanner - Software Bill of Materials Scanner

Usage:
  sbom-scanner [flags]

Flags:
  -f, --file string     Path to POM file (default: "data/pom.xml")
  -o, --output string   Output directory (default: "scan-results")
  -e, --exit-on-vuln    Exit when vulnerabilities are found (for CI/CD)
                       [true: exits with error if vulnerabilities found]
                       [false: continues even if vulnerabilities found (default)]
  -h, --help           Show help message
  -c, --check          Check and install required dependencies
`

func init() {
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:    true,
		TimestampFormat:  "2006-01-02T15:04:05-07:00",
		ForceColors:      true,
		DisableTimestamp: false,
	})
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)
}

func copyFile(src, dst string) error {
	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %v", err)
	}

	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %v", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %v", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	return nil
}

func runMavenCommand(pomPath, outputPath string) error {
	// Mutlak yolları al
	absPomPath, err := filepath.Abs(pomPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	cmd := exec.Command("mvn",
		"dependency:tree",
		"-f", absPomPath,
		"-DoutputFile="+absOutputPath,
		"-DoutputType=text")
	
	// Çalışma dizinini ayarla
	cmd.Dir = filepath.Dir(absOutputPath)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("maven command failed: %v\n%s", err, string(output))
	}

	logger.Infof("Dependency tree written to %s", outputPath)
	return nil
}

func getEffectivePom(pomPath, outputPath string) error {
	// Mutlak yolları al
	absPomPath, err := filepath.Abs(pomPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	cmd := exec.Command("mvn",
		"help:effective-pom",
		"-f", absPomPath,
		"-Doutput="+absOutputPath)
	
	// Çalışma dizinini ayarla
	cmd.Dir = filepath.Dir(absOutputPath)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("effective-pom generation failed: %v\n%s", err, string(output))
	}

	logger.Infof("Effective POM written to %s", outputPath)
	return nil
}

func generateCycloneDX(pomPath, outputPath string) error {
	// Mutlak yolları al
	absPomPath, err := filepath.Abs(pomPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	outputDir := filepath.Dir(absOutputPath)
	targetDir := filepath.Join(outputDir, "target")

	// Target dizinini oluştur
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %v", err)
	}

	cmd := exec.Command("mvn",
		"org.cyclonedx:cyclonedx-maven-plugin:2.7.9:makeAggregateBom",
		"-f", absPomPath,
		"-DoutputFormat=xml",
		"-DoutputFile=bom.xml")

	cmd.Dir = outputDir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cyclonedx generation failed: %v\n%s", err, string(output))
	}

	// target/bom.xml'i sbom.xml olarak taşı
	srcPath := filepath.Join(targetDir, "bom.xml")
	if err := os.Rename(srcPath, absOutputPath); err != nil {
		return fmt.Errorf("failed to move SBOM to output dir: %v", err)
	}

	// target dizinini temizle
	if err := os.RemoveAll(targetDir); err != nil {
		logger.Warnf("Failed to clean up target directory: %v", err)
	}

	logger.Infof("CycloneDX BOM written to %s", outputPath)
	return nil
}

func runOSVScanner(sbomPath string, exitOnVuln bool) error {
	// Mutlak yolu al
	absSbomPath, err := filepath.Abs(sbomPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	// Dosyanın varlığını kontrol et
	if _, err := os.Stat(absSbomPath); os.IsNotExist(err) {
		return fmt.Errorf("SBOM file not found: %s", absSbomPath)
	}

	outputPath := strings.TrimSuffix(sbomPath, filepath.Ext(sbomPath)) + "-vulnerabilities.json"
	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	outputFile, err := os.Create(absOutputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	cmd := exec.Command("osv-scanner",
		"--sbom", absSbomPath,
		"--format", "json")

	cmd.Stdout = outputFile
	cmd.Stderr = os.Stderr

	err = cmd.Run()

	// Vulnerability found (exit status 1)
	if isExitStatus1(err) {
		if exitOnVuln {
			return fmt.Errorf("vulnerabilities found, see details in: %s", outputPath)
		}
		logger.Warnf("Vulnerabilities found! Details: %s", outputPath)
		return nil
	}

	// Other errors
	if err != nil {
		return fmt.Errorf("osv-scanner error: %v", err)
	}

	logger.Infof("Vulnerability report written to %s", outputPath)
	return nil
}

// Check for exit status 1
func isExitStatus1(err error) bool {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode() == 1
	}
	return false
}

// checkDependencies checks if required tools are installed
func checkDependencies() error {
	// Check Maven
	if _, err := exec.LookPath("mvn"); err != nil {
		logger.Warn("Maven is not installed")
		
		// Install Maven based on OS
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			logger.Info("Installing Maven via Homebrew...")
			cmd = exec.Command("brew", "install", "maven")
		case "linux":
			logger.Info("Installing Maven via package manager...")
			// Try apt-get first (Debian/Ubuntu)
			if _, err := exec.LookPath("apt-get"); err == nil {
				cmd = exec.Command("sudo", "apt-get", "install", "-y", "maven")
			} else if _, err := exec.LookPath("yum"); err == nil {
				// Try yum (RHEL/CentOS)
				cmd = exec.Command("sudo", "yum", "install", "-y", "maven")
			} else {
				return fmt.Errorf("no supported package manager found")
			}
		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}

		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install Maven: %v", err)
		}
		logger.Info("Maven installed successfully")
	} else {
		logger.Info("Maven is already installed")
	}

	// Check OSV Scanner
	if _, err := exec.LookPath("osv-scanner"); err != nil {
		logger.Warn("OSV Scanner is not installed")
		
		// Install OSV Scanner using go install
		logger.Info("Installing OSV Scanner...")
		cmd := exec.Command("go", "install", "github.com/google/osv-scanner/cmd/osv-scanner@latest")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install OSV Scanner: %v", err)
		}
		logger.Info("OSV Scanner installed successfully")
	} else {
		logger.Info("OSV Scanner is already installed")
	}

	return nil
}

type Task struct {
	name     string
	action   func() error
	progress int
}

func main() {
	var (
		pomFile    string
		outputDir  string
		exitOnVuln bool
		showHelp   bool
		check      bool
	)

	flag.StringVar(&pomFile, "f", "data/pom.xml", "Path to POM file")
	flag.StringVar(&outputDir, "o", "scan-results", "Output directory")
	flag.BoolVar(&exitOnVuln, "e", false, "Exit when vulnerabilities are found")
	flag.BoolVar(&showHelp, "h", false, "Show help message")
	flag.BoolVar(&check, "c", false, "Check and install required dependencies")

	flag.StringVar(&pomFile, "file", "data/pom.xml", "Path to POM file")
	flag.StringVar(&outputDir, "output", "scan-results", "Output directory")
	flag.BoolVar(&exitOnVuln, "exit-on-vuln", false, "Exit when vulnerabilities are found")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&check, "check", false, "Check and install required dependencies")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, helpText)
	}

	flag.Parse()

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	// Run dependency check if requested
	if check {
		if err := checkDependencies(); err != nil {
			logger.Fatalf("Dependency check failed: %v", err)
		}
		logger.Info("All required dependencies are installed")
		os.Exit(0)
	}

	if _, err := os.Stat(pomFile); os.IsNotExist(err) {
		logger.Fatalf("POM file not found: %s", pomFile)
	}

	// Önce çıktı dizinini oluştur
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Fatalf("Failed to create directory: %v", err)
	}

	// Temizlik: Eğer klasör varsa içeriğini temizle
	if err := cleanDirectory(outputDir); err != nil {
		logger.Fatalf("Failed to clean directory: %v", err)
	}

	dstPomPath := filepath.Join(outputDir, "pom.xml")
	depsPath := filepath.Join(outputDir, "deps-tree.txt")
	effectivePomPath := filepath.Join(outputDir, "effective-pom.xml")
	sbomPath := filepath.Join(outputDir, "sbom.xml")

	// Önce POM dosyasını kopyala
	if err := copyFile(pomFile, dstPomPath); err != nil {
		logger.Fatalf("Failed to copy POM file: %v", err)
	}
	logger.Info("Copying POM File")

	tasks := []Task{
		{
			name: "Analyzing Dependencies",
			action: func() error {
				return runMavenCommand(dstPomPath, depsPath)
			},
			progress: 20,
		},
		{
			name: "Generating Effective POM",
			action: func() error {
				return getEffectivePom(dstPomPath, effectivePomPath)
			},
			progress: 20,
		},
		{
			name: "Generating CycloneDX SBOM",
			action: func() error {
				return generateCycloneDX(dstPomPath, sbomPath)
			},
			progress: 30,
		},
		{
			name: "Scanning for Vulnerabilities",
			action: func() error {
				return runOSVScanner(sbomPath, exitOnVuln)
			},
			progress: 30,
		},
	}

	// Create progress bar with clear line option
	bar := progressbar.NewOptions(100,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(30),
		progressbar.OptionSetDescription("[cyan]Running SBOM Scan[reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionShowCount(),
		progressbar.OptionFullWidth(),
		progressbar.OptionSpinnerType(14))

	startTime := time.Now()
	completedProgress := 0
	
	// İlk görev için progress bar'ı güncelle
	bar.Set(10)

	for _, task := range tasks {
		logger.Info(task.name)
		if err := task.action(); err != nil {
			fmt.Println() // Add newline before error
			logger.Fatalf("%s error: %v", task.name, err)
		}
		completedProgress += task.progress
		bar.Set(completedProgress)
		time.Sleep(100 * time.Millisecond)
	}

	// Clear the progress bar and show completion time
	bar.Clear()
	fmt.Printf("\nCompleted in %s\n", time.Since(startTime).Round(time.Second))
	logger.Info("Process completed successfully!")
}

// Klasörü temizleyen yardımcı fonksiyon
func cleanDirectory(dir string) error {
	// Klasör içeriğini oku
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	// Her bir öğeyi sil
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}

	return nil
}
