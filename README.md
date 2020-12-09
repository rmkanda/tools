# Tools

Curated list of security tools

💰 - Commercial Tool

# Secrets Detection

## Proactive

- [Talisman](https://github.com/thoughtworks/talisman) - A tool to detect and prevent secrets from getting checked in.
- [Security for Bitbucket](https://marketplace.atlassian.com/apps/1221399/security-for-bitbucket?hosting=datacenter&tab=overview) - Bitbucket plugin to detect and Block Sensitive Commits from Check-in

## Reactive

- [GitGuardian](https://www.gitguardian.com/) 💰 - Automated secrets detection & remediation.Monitor public or private source code, and other data sources as well. Detect API keys, database credentials, certificates, …
- [truffleHog](https://github.com/dxa4481/truffleHog) - Searches through git repositories for high entropy strings and secrets, digging deep into commit history
- [Gitleaks](https://github.com/zricethezav/gitleaks) - A SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.
- [ban-sensitive-files](https://github.com/bahmutov/ban-sensitive-files) - Checks filenames to be committed against a library of filename rules to prevent storing sensitive files in Git. Checks some files for sensitive contents (for example authToken inside .npmrc file).

# OSS Dependency Scanners (Application)

## Java

- [OWASP Dependency Check](https://jeremylong.github.io/DependencyCheck/) - Checks dependencies for known, publicly disclosed, vulnerabilities.

## JavaScript

- [NPM Audit](https://docs.npmjs.com/cli/audit) - Scan your project for vulnerabilities and automatically install any compatible updates to vulnerable dependencies.
- [YARN Audit](https://classic.yarnpkg.com/en/docs/cli/audit/) - Scan your project for vulnerabilities and automatically install any compatible updates to vulnerable dependencies.
- [retire.js](http://retirejs.github.io/retire.js) - Scanner detecting the use of JavaScript libraries with known vulnerabilities.
- [AuditJS](https://www.npmjs.com/package/auditjs) - Scan JavaScript (node.js inclusive) projects for vulnerable third party dependencies

## Python

- [Safety](https://pyup.io/safety/) - Safety checks your dependencies for known security vulnerabilities.
- [Requires](https://requires.io/) - Requires.io keeps your python projects secure by monitoring their dependencies.
- [Jake](https://github.com/sonatype-nexus-community/jake) - Scan Python and Conda environments for vulnerable third-party dependencies.

## Go

- [Nancy](https://github.com/sonatype-nexus-community/nancy) A tool to check for vulnerabilities in your Golang dependencies, powered by [Sonatype OSS Index](https://ossindex.sonatype.org/)

## Rust

- [cargo-audit](https://rustsec.org/) - Audit Cargo.lock for crates with security vulnerabilities reported to the RustSec Advisory Database.
- [rust-audit](https://github.com/Shnatsel/rust-audit) - Audit Rust binaries for known bugs or security vulnerabilities. This works by embedding data about the dependency tree (Cargo.lock) in JSON format into a dedicated linker section of the compiled executable.

## Mutliple Languages

- [Synk](https://snyk.io/) 💰 - Automatically find, prioritize and fix vulnerabilities in your open source dependencies throughout your development process
- [Aqua](https://www.aquasec.com/products/container-vulnerability-scanning/) 💰 - Aqua’s CyberCenter feed is updated daily, providing extensive OS and programming language coverage, application dependency detection, and reduction in false positives and false negatives based on proprietary algorithms reconciling multiple sources (NVD, vendor advisories, and Aqua research)
- [Hawkeye](https://github.com/hawkeyesec/scanner-cli) - The Hawkeye scanner-cli is a project security, vulnerability and general risk highlighting tool. It is meant to be integrated into your pre-commit hooks and your pipelines.
- [Sonatype OSS INDEX](https://ossindex.sonatype.org/) - Scan your projects for open source vulnerabilities, and build security into your development toolchain with native tools and integrations. The scan tools all utilize the OSS Index public REST API.
- [Deeptracy](https://github.com/BBVA/deeptracy) - The Security Dependency Orchestrator Service

## Automated PR (Bonus💖)

- [Renovate](https://github.com/renovatebot/renovate) - Universal dependency update tool that fits into your workflows. Automated dependency updates. Multi-platform and multi-language.
- [Dependabot](https://dependabot.com/) - Dependabot creates pull requests to keep your dependencies secure and up-to-date.
- [Sonatype Depshield](https://www.sonatype.com/depshield) - Sonatype DepShield is a free GitHub App used by developers to identify and remediate vulnerabilities in their open source dependencies.

## IDE Plugins

Most of the above tools have plugins support. Below are the some of the plugins.

- [Vuln Cost](https://snyk.io/security-scanner-vuln-cost/) - Find security vulnerabilities in open source packages while you code in JavaScript, TypeScript and HTML.
- [Grype](https://github.com/anchore/grype-vscode) - The Grype extension makes it easy to know when your project is using dependencies that have known security vulnerabilities.
- [Snyk Security Scanner](https://github.com/snyk/snyk-intellij-plugin) - The Snyk Vulnerability Scanner plugin for IDEs (like IntelliJ, eclipse, vscode) helps you find and fix security vulnerabilities in your projects, all from within your favorite IDE.
- [Trivy Vulnerability Scanner](https://marketplace.visualstudio.com/items?itemName=AquaSecurityOfficial.trivy-vulnerability-scanner) - Trivy Vulnerability Scanner is a VS Code plugin that helps you find vulnerabilities in your software projects without leaving the comfort of your VS Code window.

# SCA

- [OWASP Dependency Track](https://dependencytrack.org/) - Continuous Component Analysis Platform
- [Nexus lifecycle](https://www.sonatype.com/nexus/lifecycle) - Take full control of your software supply chain with Nexus Lifecycle. Integrate precise and accurate component intelligence directly into the development tools.
- [WhiteHat Sentinel SCA](https://www.whitehatsec.com/platform/software-composition-analysis/) - Analyzes applications for third parties and open source software to detect illegal, dangerous, or outdated code. Accelerate the time-to-market for your applications by safely and confidently utilizing open source code.

# Static Code Aanalysis

## C / C++

- [flawfinder](https://www.dwheeler.com/flawfinder) - Finds possible security weaknesses.
- [Polyspace Bug Finder](https://www.mathworks.com/products/polyspace-bug-finder.html) 💰 - Identifies run-time errors, concurrency issues, security vulnerabilities, and other defects in C and C++ embedded software.
- [Puma Scan](https://pumasecurity.io/) - Puma Scan provides real time secure code analysis for common vulnerabilities (XSS, SQLi, CSRF, LDAPi, crypto, deserialization, etc.) as development teams write code in Visual Studio.
- [Joern](https://github.com/ShiftLeftSecurity/joern) - Open-source code analysis platform for C/C++ based on code property graphs

## Java

- [Find Security Bugs](https://find-sec-bugs.github.io/) - The SpotBugs plugin for security audits of Java web applications and Android applications. (Also work with Kotlin, Groovy and Scala projects)
- [Reshift](https://www.reshiftsecurity.com/) 💰 - A source code analysis tool for detecting and managing Java security vulnerabilities.

## JavaScript

- [NodeJSScan](https://opensecurity.in/) - NodeJsScan is a static security code scanner for Node.js applications.
- [eslint-plugin-security](https://www.npmjs.com/package/eslint-plugin-security) - ESLint rules for Node Security. This project will help identify potential security hotspots, but finds a lot of false positives which need triage by a human.
- [tslint-plugin-security](https://www.npmjs.com/package/tslint-config-security) - TSLint rules for Node Security. This project will help identify potential security hotspots, but finds a lot of false positives which need triage by a human.

## Go

- [gosec](https://github.com/securego/gosec) - Golang Security Checker inspects source code for security problems by scanning the Go AST.
- [golangci-lint] (https://github.com/golangci/golangci-lint) - It runs linters in parallel, uses caching, supports yaml config, has integrations with all major IDE and has dozens of linters included.

## Elixer

- [sobelow](https://github.com/nccgroup/sobelow) - Security-focused static analysis for the Phoenix Framework.

## PHP

- [Parse](https://github.com/psecio/parse) - A Static Security Scanner.
- [Progpilot](https://github.com/designsecurity/progpilot) - A static analysis tool for security purposes.

## Python

- [bandit](https://bandit.readthedocs.io/en/latest) - A tool to find common security issues in Python code.
- [Pysa (Python Static Analyzer)](https://pyre-check.org/docs/pysa-basics.html) - A tool based on Facebook's [pyre-check](https://github.com/facebook/pyre-check/) to identify potential security issues in Python code identified with taint analysis.
- [Dlint](https://github.com/dlint-py/dlint) - A tool for ensuring Python code is secure.

## Ruby

- [RuboCop](https://rubocop.org/) - A Ruby code style checker (linter) and formatter based on the community-driven Ruby Style Guide.
- [brakeman](https://brakemanscanner.org/) - A Ruby on Rails Static Analysis Security Tool
- [Railroader](https://railroader.org/) - An open source static analysis security vulnerability scanner for Ruby on Rails applications - fork of the Brakeman.

## Android / iOS

- [iblessing](https://github.com/Soulghost/iblessing) - iblessing is an iOS security exploiting toolkit. It can be used for reverse engineering, binary analysis and vulnerability mining.
- [Oversecured](https://oversecured.com/) 💰 - A mobile app vulnerability scanner, designed for security researchers and bug bounty hackers. It also allows integrations into the DevOps process for businesses.
- [qark](https://github.com/linkedin/qark) - Tool to look for several security related Android application vulnerabilities.

## Binaries

- [BinSkim](https://github.com/Microsoft/binskim) - A binary static analysis tool that provides security and correctness results for Windows portable executables.
- [Black Duck](https://www.blackducksoftware.com/) 💰 - Tool to analyze source code and binaries for reusable code, necessary licenses and potential security aspects.
- [Ghidra](https://ghidra-sre.org/) - A software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate in support of the Cybersecurity mission

## IaC - Infrasturcutre as code

### Docker

- [dagda](https://github.com/eliasgranderubio/dagda) - Perform static analysis of known vulnerabilities in docker images/containers.
- [dockle](https://github.com/goodwithtech/dockle) - Container Image Linter for Security, Helping build the Best-Practice Docker Image, Easy to start

### Kubernetes

- [KUBESEC.IO](https://kubesec.io/) - Security risk analysis for Kubernetes resources
- [kubeaudit](https://github.com/Shopify/kubeaudit) - kubeaudit helps you audit your Kubernetes clusters against common security controls

### Terraform

- [checkov](https://www.checkov.io/) - Static analysis tool for Terraform files (tf>=v0.12), preventing cloud misconfigs at build time.
- [terrascan](https://github.com/accurics/terrascan) - Detect compliance and security violations across Infrastructure as Code to mitigate risk before provisioning cloud native infrastructure.
- [terraform-compliance](https://terraform-compliance.com/) - A lightweight, compliance- and security focused, BDD test framework against Terraform.
- [tfsec](https://github.com/tfsec/tfsec) - tfsec uses static analysis of your terraform templates to spot potential security issues. Now with terraform v0.12+ support.

## Multiple Languages

- [ShiftLeft Scan (skæn)](https://slscan.io/) - Scan is a free open-source DevSecOps platform for detecting security issues in source code and dependencies. It supports a broad range of languages and CI/CD pipelines.
- [Coverity®](https://scan.coverity.com/) 💰 - Synopsys Coverity supports 20 languages and over 70 frameworks including
- [Checkmarx SAST (CxSAST)](https://www.checkmarx.com/products/static-application-security-testing) 💰 - An enterprise-grade flexible and accurate static analysis solution used to identify hundreds of security vulnerabilities in custom code
- [Fortify Static Code Analyzer](https://www.microfocus.com/en-us/products/static-code-analysis-sast/overview) 💰 - A commercial static analysis platform that supports the scanning of 27 major programming languages.
- [Veracode](https://www.veracode.com/products/binary-static-analysis-sast) 💰 - Find flaws in binaries and bytecode without requiring source. Support all major programming languages.
- [Application Inspector](https://www.ptsecurity.com/ww-en/products/ai) 💰 - Commercial Static Code Analysis which generates exploits to verify vulnerabilities.
- [CodePatrol](https://cyber-security.claranet.fr/en/codepatrol) 💰 - Automated SAST code reviews driven by security, supports 15+ languages and includes security training.
- [CodeScan](https://www.codescan.io/) 💰 - Code Quality and Security for Salesforce Developers. Made exclusively for the Salesforce platform, CodeScan’s code analysis solutions provide you with total visibility into your code health.
- [dawnscanner](https://github.com/thesp0nge/dawnscanner) - A static analysis security scanner for ruby written web applications. It supports Sinatra, Padrino and Ruby on Rails frameworks.
- [DeepCode](https://www.deepcode.ai/) 💰 - DeepCode finds bugs, security vulnerabilities, performance and API issues based on AI. DeepCode's speed of analysis allow us to analyse your code in real time and deliver results when you hit the save button in your IDE. Supported languages are Java, C/C++, JavaScript, Python, and TypeScript. Integrations with GitHub, BitBucket and Gitlab.
- [DeepSource](https://deepsource.io/) 💰 - In-depth static analysis to find issues in verticals of bug risks, security, anti-patterns, performance, documentation and style. Native integrations with GitHub, GitLab and Bitbucket. Less than 5% false positives.
- [InsiderSec](https://insidersec.io/) - A open source Static Application Security Testing tool (SAST) written in GoLang for Java (Maven and Android), Kotlin (Android), Swift (iOS), .NET Full Framework, C# and Javascript (Node.js).
- [Klocwork](https://www.perforce.com/products/klocwork) 💰 - Quality and Security Static analysis for C/C++, Java and C#.
- [Semmle QL and LGTM]() 💰 - Find security vulnerabilities, variants, and critical code quality issues using queries over source code. Automatic PR code review; free for public GitHub/Bitbucket repo: [LGTM.com](https://lgtm.com/).
- [Semgrep](https://github.com/returntocorp/semgrep) - Lightweight static analysis for many languages. Find bug variants with patterns that look like source code.
- [SonarCloud](https://sonarcloud.io/) 💰 - Multi-language cloud-based static code analysis. History, trends, security hot-spots, pull request analysis and more. Free for open source.
- [WhiteHat Application Security Platform](https://www.whitehatsec.com/platform/static-application-security-testing) 💰 - WhiteHat Scout (for Developers) combined with WhiteHat Sentinel Source (for Operations) supporting WhiteHat Top 40 and OWASP Top 10.
- [Xanitizer](https://xanitizer.com/) 💰 - Xanitizer finds security vulnerabilities in web applications. It supports Java, Scala, JavaScript and TypeScript.

# OSS License Scanner

- [License Finder](https://github.com/pivotal/LicenseFinder) - LicenseFinder works with your package managers to find dependencies, detect the licenses of the packages in them, compare those licenses against a user-defined list of permitted licenses, and give you an actionable exception report.
- [Fossa](https://fossa.com/) 💰 - Get continuous compliance with code SCA featuring audit-grade reporting and comprehensive dependency inventory.
- [WhiteSource](https://www.whitesourcesoftware.com/) 💰 - Detect and remediate open source security and compliance issues in real-time, without the headache
- [Nexus auditor](https://www.sonatype.com/nexus/auditor) 💰 - Generate a Software Bill of Materials and Triage License, Security Risk within Third Party Applications and Continuously Monitor Apps for New Vulnerabilities
- [Licensebat](https://licensebat.com/) 💰 - Licensebat seamlessly integrates with your GitHub build pipeline to make sure your current and future dependencies comply with your license policies.
- [Black Duck®](https://www.synopsys.com/software-integrity/security-testing/static-analysis-sast.html) 💰 - Helps teams manage the security, quality, and license compliance risks that come from the use of open source and third-party code in applications and containers.
- [FOSSology](https://www.fossology.org/) - a open source license compliance software system and toolkit. As a toolkit you can run license, copyright and export control scans from the command line.
- [FOSSID](https://fossid.com/) - A Software Composition Analysis tool that scans your code for open source licenses and vulnerabilities, and gives you full transparency and control of your software products and services.
- [Palamida](https://www.almtoolbox.com/palamida.php) - Palamida is the leader in advanced techniques to identify Open Source and other third party software in use within your development projects.
- [OSS Review Toolkit]
- [ClearlyDefined](https://clearlydefined.io/) - Lack of clarity around licenses and security vulnerabilities reduces engagement — that means fewer users, fewer contributors and a smaller community.

# Container Scanner

- [Trivy](https://github.com/aquasecurity/trivy) The most comprehensive and easy-to-use open source vulnerability scanner for container images
- [Anchore inline-scan container](https://github.com/anchore/ci-tools) - Anchore container analysis and scan provided as inline scanner
- [grype](https://github.com/anchore/grype) A vulnerability scanner for container images and filesystems

# DAST

- [Acunetix](https://www.acunetix.com) 💰 - scans your entire website for security vulnerabilities in front-end & server-side application and gives you actionable results.

# Hardening and Compliance

## VMs

- [OpenSCAP](https://www.open-scap.org/) - The OpenSCAP ecosystem provides multiple tools to assist administrators and auditors with assessment, measurement, and enforcement of security baselines.
- [Lynis](https://cisofy.com/lynis/) - Auditing, system hardening, compliance testing
- [OpenVAS](https://www.greenbone.net/en/) - A full-featured vulnerability scanner. Its capabilities include unauthenticated testing, authenticated testing, various high level and low level Internet and industrial protocols, performance tuning for large-scale scans and a powerful internal programming language to implement any type of vulnerability test.

## Cloud

- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Setection of security risks in cloud infrastructure accounts, including: AWS, Microsoft Azure, GCP, Oracle Cloud Infrastructure (OCI), and GitHub.
- [Scout Suite](https://github.com/nccgroup/ScoutSuite) - Scout Suite is an open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments. Using the APIs exposed by cloud providers, Scout Suite gathers configuration data for manual inspection and highlights risk areas.
- [Prisma Cloud 2.0](https://www.paloaltonetworks.com/prisma/cloud) 💰 - Cloud Native Security Platform (CNSP) - The Clouds of Today, Secured Against the Threats of Tomorrow
- [Sysdig Platform](https://sysdig.com/secure-devops-platform/) 💰 - Ship cloud apps faster by embedding security, compliance, and performance into your DevOps workflow
- [Panther](https://github.com/panther-labs/panther) - Panther is a platform for detecting threats with log data, improving cloud security posture, and conducting investigations.
- [Fugue Compliance](https://www.fugue.co/cloud-infrastructure-compliance) 💰 - Demonstrate compliance to management and auditors at any time with dashboards, reports, and visualizations.

## Kubernetes

- [Kube-bench](https://github.com/aquasecurity/kube-bench) Tool for checking Kubernetes compliance with the Center for Internet Security (CIS) Benchmark
- [Kube-hunter](https://github.com/aquasecurity/kube-bench) Penetration testing that simulates dozens of attack vectors on your Kubernetes cluster
- [Kubei](https://github.com/Portshift/kubei) - Kubei is a flexible Kubernetes runtime scanner, scanning images of worker and Kubernetes nodes providing accurate vulnerabilities assessment
- [kube-forensics](https://github.com/keikoproj/kube-forensics) - kube-forensics allows a cluster administrator to dump the current state of a running pod and all its containers so that security professionals can perform off-line forensic analysis.

# IDS

- [OSSEC](https://github.com/ossec/ossec-hids) - An Open Source Host-based Intrusion Detection System that performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response.

# [GitHub Apps](https://github.com/marketplace?category=security&type=apps)

## Free for Public and Private Repos

- [Dependabot](https://github.com/marketplace/dependabot-preview) - GitHub Dependabot can maintain your repository's dependencies automatically.
- [WhiteSource Bolt](https://github.com/marketplace/whitesource-bolt) - Continuously scans all your repos, detects vulnerabilities in open source components and provides fixes. It supports both private and public repositories. 200 programming languages support.
- [WhiteSource Renovate](https://github.com/marketplace/renovate) - Automatically update dependencies using convenient Pull Requests
- [Sonatype DepShield](https://github.com/marketplace/sonatype-depshield) - Identify and remediate vulnerabilities in their open source dependencies.

## Free for Public and Open Source Repos

- [Depfu](https://depfu.com/) 💰 - [Depfu](https://github.com/marketplace/depfu) is like a colleague who sends you pull requests with all the info you need about a update. You stay in control if and when to merge. Only for JavaScript and Ruby.

# [GitHub Actions](https://github.com/marketplace?category=security&type=actions)

Most of the tools now have github action support - Refer the complete list here - https://github.com/marketplace?category=security&type=actions

# Password Mangers

- [Keeper Password Manager & Digital Vault](https://www.keepersecurity.com/) - 💰
- [Dashlane](https://www.dashlane.com/) - 💰
- [1Password](https://1password.com/) - 💰
- [LastPass](https://www.lastpass.com/) - 💰
- [KeePass](https://keepass.info/) - KeePass is a free open source password manager, which helps you to manage your passwords in a secure way. You can store all your passwords in one database, which is locked with a master key.
- [Cyph] - (https://www.cyph.com/)

# Standards

- [CWE](https://cwe.mitre.org/data/index.html) - Common Weakness Enumeration (CWE™) is a list of software and hardware weaknesses types.
- [CAPEC](https://capec.mitre.org/index.html) - The Common Attack Pattern Enumeration and Classification (CAPEC™) effort provides a publicly available catalog of attack patterns along with a comprehensive schema and classification taxonomy.
- [WASC](http://projects.webappsec.org/w/page/13246978/Threat%20Classification) - The WASC Threat Classification is a cooperative effort to clarify and organize the threats to the security of a web site. The members of the Web Application Security Consortium have created this project to develop and promote industry standard terminology for describing these issues.

# Free Tranings

- [Cloud Security Alliance (CSA)]
