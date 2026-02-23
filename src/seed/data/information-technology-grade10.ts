import type { ModuleSeed } from "../types.js";

/**
 * CAPS-aligned Information Technology Grade 10 Modules
 *
 * Based on the IT CAPS 2024 Section 3 document.
 * Grade 10 introduces foundational computing concepts, basic hardware/software,
 * introduction to programming in Delphi, and introductory social implications.
 *
 * Term 1: Basic concepts, data representation, intro algorithms, intro solution development
 * Term 2: Hardware, system software, networks, e-communications, selection & strings
 * Term 3: Computer management, internet & WWW, loops, strings, patterns, PAT
 * Term 4: Internet services, consolidation, text files, PAT finalization
 */

export const grade10Modules: ModuleSeed[] = [
  // ─── TERM 1 ───────────────────────────────────────────────
  {
    key: "it10-basic-concepts",
    title: "Basic Computing Concepts",
    description:
      "Understand what a computer system is, distinguish between hardware and software, and learn about data representation including number systems and units of storage.",
    grade: 10,
    order: 1,
    capsTags: ["systems", "hardware", "software", "data-representation"],
    lessons: [
      {
        title: "What is a computer system?",
        type: "text",
        order: 1,
        content:
          "# Computer Systems\n\nA **computer system** consists of hardware, software, and a user working together to process data into useful information.\n\n## Components of a Computer System\n- **Input devices**: keyboard, mouse, scanner, microphone — they send data to the computer.\n- **Processing**: the CPU (Central Processing Unit) carries out instructions.\n- **Output devices**: monitor, printer, speakers — they present results.\n- **Storage**: hard drive, SSD, USB flash drive — they save data for later use.\n\n## Hardware vs Software\n- **Hardware**: the physical parts you can touch (e.g. keyboard, monitor, motherboard).\n- **Software**: the programs and instructions that tell hardware what to do.\n  - *System software*: operating systems (Windows, Linux), utilities.\n  - *Application software*: word processors, browsers, games.\n\n## Firmware\nFirmware is software permanently stored on a hardware chip (e.g. BIOS/UEFI). It starts the computer before the OS loads.\n",
      },
      {
        title: "Data representation and number systems",
        type: "text",
        order: 2,
        content:
          '# Data Representation\n\nComputers store all data as **binary** (0s and 1s).\n\n## Number Systems\n| System | Base | Digits Used | Example |\n|--------|------|-------------|---------|\n| Binary | 2 | 0, 1 | 1010 |\n| Decimal | 10 | 0–9 | 10 |\n| Hexadecimal | 16 | 0–9, A–F | A |\n\n## Converting Binary to Decimal\nEach bit position has a value: 128, 64, 32, 16, 8, 4, 2, 1.\n\nExample: `1010` in binary = 8 + 0 + 2 + 0 = **10** in decimal.\n\n## Units of Storage\n| Unit | Size |\n|------|------|\n| Bit | 0 or 1 |\n| Byte | 8 bits |\n| Kilobyte (KB) | 1 024 bytes |\n| Megabyte (MB) | 1 024 KB |\n| Gigabyte (GB) | 1 024 MB |\n| Terabyte (TB) | 1 024 GB |\n\n## Character Encoding\n- **ASCII** uses 7 or 8 bits per character.\n  - "A" = 65, "a" = 97, "0" = 48.\n- **Unicode** extends ASCII to support all world languages.\n',
      },
      {
        title: "Social implications — Introduction",
        type: "text",
        order: 3,
        content:
          "# Social Implications of Computing\n\n## The Digital Divide\nThe **digital divide** is the gap between people who have access to modern technology and those who do not. In South Africa, rural areas often lack internet connectivity and devices.\n\n## Ergonomics\nErgonomics is the science of designing a comfortable and safe workspace:\n- Monitor at eye level, about an arm's length away.\n- Feet flat on the floor, back supported.\n- Take breaks every 30–45 minutes to prevent RSI (Repetitive Strain Injury).\n\n## Green Computing\n- Turn off computers when not in use.\n- Recycle e-waste responsibly.\n- Use energy-efficient hardware.\n\n## Ethics in Computing\n- Respect intellectual property and copyright.\n- Do not copy software illegally (piracy).\n- Respect privacy — do not access others' files without permission.\n",
      },
    ],
    quiz: {
      title: "Basic Computing Concepts Quiz",
      description: "Test your understanding of computer systems, data representation, and social implications.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Which part of a computer system carries out instructions?",
          type: "multiple_choice",
          options: ["CPU", "RAM", "Hard drive", "Monitor"],
          correctAnswer: "CPU",
          explanation: "The CPU (Central Processing Unit) processes instructions.",
        },
        {
          questionText: "Convert the binary number 1101 to decimal.",
          type: "short_answer",
          correctAnswer: "13",
          explanation: "1101 = 8 + 4 + 0 + 1 = 13.",
        },
        {
          questionText: "How many bytes are in a kilobyte?",
          type: "multiple_choice",
          options: ["1024", "1000", "512", "2048"],
          correctAnswer: "1024",
          explanation: "1 KB = 1024 bytes in binary-based computing.",
        },
        {
          questionText: "What is the ASCII code for the character 'A'?",
          type: "short_answer",
          correctAnswer: "65",
          explanation: "In ASCII, uppercase A is code 65.",
        },
        {
          questionText: "What is the digital divide?",
          type: "short_answer",
          correctAnswer:
            "The gap between people who have access to modern technology and those who do not.",
          explanation:
            "The digital divide is a key social implication topic in CAPS IT.",
        },
        {
          questionText: "Explain the difference between hardware and software.",
          type: "essay",
          correctAnswer:
            "Hardware refers to the physical components of a computer that you can touch (e.g., keyboard, monitor, CPU). Software refers to the programs and instructions that tell the hardware what to do (e.g., operating systems, applications).",
          explanation:
            "Understanding the hardware/software distinction is fundamental.",
        },
      ],
    },
  },
  {
    key: "it10-intro-algorithms",
    title: "Introduction to Algorithms",
    description:
      "Learn what an algorithm is, how to plan solutions using pseudocode and flowcharts, and how to use IPO charts to structure problem solving.",
    grade: 10,
    order: 2,
    capsTags: ["algorithms", "pseudocode", "flowcharts", "ipo"],
    lessons: [
      {
        title: "What is an algorithm?",
        type: "text",
        order: 1,
        content:
          "# Algorithms\n\nAn **algorithm** is a step-by-step set of instructions to solve a problem or complete a task.\n\n## Characteristics of a Good Algorithm\n1. **Precise** — each step is clear and unambiguous.\n2. **Ordered** — steps follow a logical sequence.\n3. **Finite** — it must eventually end.\n4. **Produces output** — it gives a result.\n\n## Everyday Example\nAlgorithm for making tea:\n1. Boil water.\n2. Place teabag in cup.\n3. Pour boiling water into cup.\n4. Wait 3 minutes.\n5. Remove teabag.\n6. Add milk and sugar if desired.\n\n## Why Algorithms Matter in Programming\nBefore writing code in Delphi, you should plan your solution as an algorithm. This helps avoid errors and keeps your logic clear.\n",
      },
      {
        title: "Pseudocode and flowcharts",
        type: "text",
        order: 2,
        content:
          "# Pseudocode and Flowcharts\n\n## Pseudocode\nPseudocode is structured English that describes an algorithm without using a specific programming language.\n\n**Example — Check if a number is positive:**\n```\nINPUT number\nIF number > 0 THEN\n  DISPLAY \"Positive\"\nELSE\n  DISPLAY \"Not positive\"\nENDIF\n```\n\n## Flowcharts\nFlowcharts use shapes to represent steps:\n- **Oval**: Start / End\n- **Parallelogram**: Input / Output\n- **Rectangle**: Process / Action\n- **Diamond**: Decision (Yes/No)\n- **Arrows**: Flow direction\n\n## IPO Charts\nAn **IPO chart** (Input-Process-Output) helps you plan:\n| Input | Process | Output |\n|-------|---------|--------|\n| Two numbers | Add them | Display sum |\n\nAlways create an IPO chart before coding to clarify what data comes in, what happens to it, and what result is produced.\n",
      },
      {
        title: "Tracing algorithms",
        type: "text",
        order: 3,
        content:
          "# Tracing Algorithms\n\n**Tracing** means stepping through an algorithm line by line and tracking the values of variables at each step.\n\n## Trace Table Example\nAlgorithm:\n```\nSET total = 0\nFOR i = 1 TO 4\n  total = total + i\nENDFOR\nDISPLAY total\n```\n\n| Step | i | total |\n|------|---|-------|\n| Start | — | 0 |\n| Loop 1 | 1 | 1 |\n| Loop 2 | 2 | 3 |\n| Loop 3 | 3 | 6 |\n| Loop 4 | 4 | 10 |\n\nFinal output: **10**\n\n## Why Tracing Matters\n- Helps you find logic errors.\n- In exams, you earn marks for showing correct tracing even if your code has small errors.\n- Practice tracing with loops, conditions, and running totals.\n",
      },
    ],
    quiz: {
      title: "Introduction to Algorithms Quiz",
      description: "Test your understanding of algorithms, pseudocode, flowcharts, and tracing.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Define an algorithm.",
          type: "short_answer",
          correctAnswer:
            "A step-by-step set of instructions to solve a problem.",
          explanation: "An algorithm must be precise, ordered, and finite.",
        },
        {
          questionText:
            "Which flowchart shape represents a decision?",
          type: "multiple_choice",
          options: ["Diamond", "Rectangle", "Oval", "Parallelogram"],
          correctAnswer: "Diamond",
          explanation: "A diamond shape is used for Yes/No decisions.",
        },
        {
          questionText: "What does IPO stand for?",
          type: "multiple_choice",
          options: [
            "Input, Process, Output",
            "Information, Program, Output",
            "Input, Print, Output",
            "Information, Process, Operation",
          ],
          correctAnswer: "Input, Process, Output",
          explanation: "IPO charts plan the input, processing, and output of a solution.",
        },
        {
          questionText:
            "Trace the algorithm: SET x = 5, SET y = x * 2 + 1. What is y?",
          type: "short_answer",
          correctAnswer: "11",
          explanation: "x = 5, y = 5 * 2 + 1 = 11.",
        },
        {
          questionText:
            "Explain why tracing algorithms is important before writing code.",
          type: "essay",
          correctAnswer:
            "Tracing helps verify that your logic is correct by stepping through each instruction and tracking variable values. It catches errors before you code and earns marks in exams even if syntax is imperfect.",
          explanation:
            "Tracing is a key exam skill in CAPS IT.",
        },
      ],
    },
  },
  {
    key: "it10-intro-delphi",
    title: "Introduction to Delphi and Solution Development",
    description:
      "Get started with the Delphi IDE, understand the GUI form designer, and write your first programs using variables, data types, and basic input/output.",
    grade: 10,
    order: 3,
    capsTags: ["delphi", "ide", "variables", "data-types", "gui"],
    lessons: [
      {
        title: "The Delphi IDE and GUI components",
        type: "text",
        order: 1,
        content:
          "# The Delphi IDE\n\nDelphi is an **Integrated Development Environment** (IDE) used in South African IT classes for Object Pascal programming.\n\n## Key Parts of the IDE\n- **Form Designer**: drag and drop GUI components onto a form.\n- **Code Editor**: write Object Pascal code.\n- **Object Inspector**: set properties (Text, Caption, Color, etc.).\n- **Project Manager**: manage files in your project.\n\n## Common GUI Components\n| Component | Purpose | Key Property |\n|-----------|---------|---------------|\n| TButton | User clicks to trigger an action | Caption |\n| TEdit | Single-line text input | Text |\n| TLabel | Display text (read-only) | Caption |\n| TMemo / TRichEdit | Multi-line text display | Lines |\n| TRadioGroup | Choose one option from a group | ItemIndex |\n| TComboBox | Drop-down selection list | Text, Items |\n| TCheckBox | Toggle on/off | Checked |\n| TImage | Display an image | Picture |\n\n## Event-Driven Programming\nDelphi programs respond to **events** (e.g., button clicks). Double-click a button to create an `OnClick` event handler.\n",
      },
      {
        title: "Variables and data types",
        type: "text",
        order: 2,
        content:
          "# Variables and Data Types\n\n## What is a Variable?\nA **variable** is a named storage location in memory that holds a value. You must **declare** variables before using them.\n\n```pascal\nvar\n  name: String;\n  age: Integer;\n  price: Real;\n  passed: Boolean;\n```\n\n## Common Data Types\n| Type | Description | Example |\n|------|-------------|----------|\n| Integer | Whole numbers | 42, -7 |\n| Real | Decimal numbers | 3.14, -0.5 |\n| String | Text (sequence of characters) | 'Hello' |\n| Char | Single character | 'A' |\n| Boolean | True or False | True |\n\n## Type Conversion\n- `StrToInt('42')` → converts string to integer.\n- `IntToStr(42)` → converts integer to string.\n- `StrToFloat('3.14')` → converts string to real number.\n- `FloatToStr(3.14)` → converts real to string.\n\n## Constants\nA **constant** stores a value that never changes:\n```pascal\nconst\n  PI = 3.14159;\n  MAX_STUDENTS = 40;\n```\n",
      },
      {
        title: "Basic input and output",
        type: "text",
        order: 3,
        content:
          "# Input and Output in Delphi\n\n## Reading Input from GUI Components\n```pascal\n// Read text from an Edit box\nvar sName: String;\nsName := edtName.Text;\n\n// Convert to a number\nvar iAge: Integer;\niAge := StrToInt(edtAge.Text);\n```\n\n## Displaying Output\n```pascal\n// Display in a Label\nlblResult.Caption := 'Hello, ' + sName;\n\n// Display in a Memo (multi-line)\nmemOutput.Lines.Add('Age: ' + IntToStr(iAge));\n\n// Show a message dialog\nShowMessage('Welcome to IT!');\n```\n\n## Arithmetic Operators\n| Operator | Meaning | Example |\n|----------|---------|----------|\n| + | Addition | 5 + 3 = 8 |\n| - | Subtraction | 10 - 4 = 6 |\n| * | Multiplication | 3 * 7 = 21 |\n| / | Real division | 7 / 2 = 3.5 |\n| div | Integer division | 7 div 2 = 3 |\n| mod | Remainder | 7 mod 2 = 1 |\n\n## A Complete Example\n```pascal\nprocedure TfrmMain.btnCalcClick(Sender: TObject);\nvar\n  iNum1, iNum2, iSum: Integer;\nbegin\n  iNum1 := StrToInt(edtNum1.Text);\n  iNum2 := StrToInt(edtNum2.Text);\n  iSum := iNum1 + iNum2;\n  lblResult.Caption := 'Sum = ' + IntToStr(iSum);\nend;\n```\n",
      },
    ],
    quiz: {
      title: "Introduction to Delphi Quiz",
      description:
        "Test your knowledge of the Delphi IDE, variables, data types, and basic I/O.",
      difficulty: "easy",
      questions: [
        {
          questionText:
            "Which Delphi component is used for single-line text input?",
          type: "multiple_choice",
          options: ["TEdit", "TLabel", "TMemo", "TButton"],
          correctAnswer: "TEdit",
          explanation: "TEdit provides a single-line input field.",
        },
        {
          questionText:
            "What data type would you use to store a decimal number like 3.14?",
          type: "multiple_choice",
          options: ["Real", "Integer", "String", "Boolean"],
          correctAnswer: "Real",
          explanation:
            "Real (or Double) stores decimal numbers.",
        },
        {
          questionText:
            "Write the Delphi function call to convert the string '25' to an integer.",
          type: "short_answer",
          correctAnswer: "StrToInt('25')",
          explanation:
            "StrToInt converts a string to an integer value.",
        },
        {
          questionText: "What is the result of 17 mod 5?",
          type: "short_answer",
          correctAnswer: "2",
          explanation:
            "17 mod 5 = 2 because 17 = 3 * 5 + 2.",
        },
        {
          questionText: "What is the result of 17 div 5?",
          type: "multiple_choice",
          options: ["3", "3.4", "2", "4"],
          correctAnswer: "3",
          explanation: "div performs integer division: 17 div 5 = 3.",
        },
        {
          questionText:
            "Explain the difference between a variable and a constant in Delphi.",
          type: "essay",
          correctAnswer:
            "A variable is a named storage location whose value can change during program execution. A constant holds a fixed value that cannot be changed once assigned. Variables are declared with 'var' and constants with 'const'.",
          explanation:
            "Variables change; constants do not — a fundamental concept.",
        },
      ],
    },
  },
  // ─── TERM 2 ───────────────────────────────────────────────
  {
    key: "it10-hardware",
    title: "Hardware Components",
    description:
      "Identify and explain the function of hardware components: input/output devices, storage, the system unit, ports, and connections.",
    grade: 10,
    order: 4,
    capsTags: ["hardware", "input", "output", "storage", "ports"],
    lessons: [
      {
        title: "Input and output devices",
        type: "text",
        order: 1,
        content:
          "# Input and Output Devices\n\n## Input Devices\nInput devices send data **into** the computer:\n- **Keyboard**: text entry.\n- **Mouse / Touchpad**: pointing and clicking.\n- **Scanner**: digitizes physical documents.\n- **Microphone**: captures audio.\n- **Webcam**: captures video.\n- **Barcode reader**: reads barcodes for stock systems.\n- **Touchscreen**: both input (touch) and output (display).\n\n## Output Devices\nOutput devices present processed data:\n- **Monitor / Screen**: visual display (LCD, LED, OLED).\n- **Printer**: hard copy output (inkjet, laser, 3D printer).\n- **Speakers / Headphones**: audio output.\n- **Projector**: large-screen display.\n\n## Dual Devices\nSome devices are both input and output:\n- **Touchscreen**: displays info and accepts touch.\n- **Multi-function printer**: prints, scans, copies.\n",
      },
      {
        title: "Storage devices and the system unit",
        type: "text",
        order: 2,
        content:
          "# Storage and the System Unit\n\n## Types of Storage\n| Type | Examples | Volatile? |\n|------|----------|----------|\n| Primary (RAM) | DDR4 RAM modules | Yes — loses data when power off |\n| Primary (ROM) | BIOS chip | No — permanent |\n| Secondary | HDD, SSD, USB flash drive | No — persistent |\n| Optical | CD, DVD, Blu-ray | No |\n| Cloud | Google Drive, OneDrive | No — stored remotely |\n\n## HDD vs SSD\n- **HDD** (Hard Disk Drive): magnetic platters, cheaper per GB, slower, moving parts.\n- **SSD** (Solid State Drive): flash memory, faster, no moving parts, more durable, more expensive.\n\n## Inside the System Unit\n- **Motherboard**: main circuit board connecting all components.\n- **CPU**: processes instructions (the \"brain\").\n- **RAM**: temporary working memory.\n- **Power supply unit (PSU)**: provides electricity.\n- **GPU (Graphics Processing Unit)**: processes graphics.\n- **Expansion slots**: for adding cards (network, sound, graphics).\n\n## Ports and Connections\n- **USB** (Universal Serial Bus): most common for peripherals.\n- **HDMI**: video and audio to monitors/TVs.\n- **Ethernet (RJ-45)**: wired network connection.\n- **3.5mm audio jack**: headphones/microphone.\n- **Thunderbolt / USB-C**: high-speed data and power.\n",
      },
    ],
    quiz: {
      title: "Hardware Components Quiz",
      description: "Test your knowledge of input/output devices, storage, and the system unit.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Name two input devices.",
          type: "short_answer",
          correctAnswer: "Keyboard and mouse",
          explanation:
            "Keyboard and mouse are the most common input devices.",
        },
        {
          questionText: "Which type of storage is volatile?",
          type: "multiple_choice",
          options: ["RAM", "SSD", "HDD", "USB flash drive"],
          correctAnswer: "RAM",
          explanation:
            "RAM loses its data when the computer is switched off.",
        },
        {
          questionText: "What is the main advantage of an SSD over an HDD?",
          type: "multiple_choice",
          options: [
            "Faster read/write speeds",
            "Cheaper per gigabyte",
            "Larger maximum capacity",
            "Uses magnetic platters",
          ],
          correctAnswer: "Faster read/write speeds",
          explanation:
            "SSDs use flash memory with no moving parts, making them much faster.",
        },
        {
          questionText: "What is the function of the motherboard?",
          type: "short_answer",
          correctAnswer:
            "The main circuit board that connects all computer components together.",
          explanation:
            "All components communicate through the motherboard.",
        },
        {
          questionText:
            "Which port is most commonly used to connect a monitor for both video and audio?",
          type: "multiple_choice",
          options: ["HDMI", "USB", "Ethernet", "3.5mm audio jack"],
          correctAnswer: "HDMI",
          explanation: "HDMI carries both video and audio signals.",
        },
      ],
    },
  },
  {
    key: "it10-system-software",
    title: "System Software and Networks",
    description:
      "Understand operating systems, utility software, device drivers, and the basics of computer networks.",
    grade: 10,
    order: 5,
    capsTags: ["software", "os", "utilities", "networks"],
    lessons: [
      {
        title: "Operating systems and utility software",
        type: "text",
        order: 1,
        content:
          "# System Software\n\n## Operating System (OS)\nThe **operating system** manages hardware resources and provides a platform for applications.\n\n### Functions of an OS\n- **Process management**: runs multiple programs simultaneously.\n- **Memory management**: allocates RAM to programs.\n- **File management**: organizes files in folders/directories.\n- **Device management**: communicates with hardware via drivers.\n- **User interface**: GUI (graphical) or CLI (command-line).\n\n### Examples\n- **Windows** (Microsoft) — most common on desktops in SA schools.\n- **macOS** (Apple) — for Mac computers.\n- **Linux** (open source) — Ubuntu, Mint, etc.\n- **Android / iOS** — mobile operating systems.\n\n## Utility Software\nUtility programs perform maintenance tasks:\n- **Antivirus**: detects and removes malware.\n- **Disk Defragmenter**: reorganizes data on HDD for speed (not needed for SSD).\n- **Backup software**: creates copies of files for safety.\n- **File compression**: reduces file size (ZIP, RAR).\n- **Disk cleanup**: removes temporary and unnecessary files.\n\n## Device Drivers\nA **driver** is software that allows the OS to communicate with a specific hardware device (e.g., printer driver, graphics driver).\n",
      },
      {
        title: "Introduction to networks",
        type: "text",
        order: 2,
        content:
          "# Computer Networks\n\nA **computer network** connects two or more devices to share resources and communicate.\n\n## Types of Networks\n| Type | Description | Range |\n|------|-------------|-------|\n| LAN | Local Area Network | Single building/campus |\n| WAN | Wide Area Network | Cities/countries |\n| PAN | Personal Area Network | Within a few meters |\n| MAN | Metropolitan Area Network | City-wide |\n\n## Network Components\n- **Router**: directs data between networks.\n- **Switch**: connects devices within a LAN.\n- **Modem**: converts signals for internet access.\n- **NIC (Network Interface Card)**: allows a device to connect to a network.\n- **Cables**: Ethernet (wired), fibre optic.\n\n## Wired vs Wireless\n| Feature | Wired | Wireless |\n|---------|-------|----------|\n| Speed | Generally faster | Improving but slower |\n| Security | More secure | Vulnerable to interception |\n| Mobility | Limited | Free movement |\n| Setup | Cables needed | No cables |\n\n## Network Topologies\n- **Star**: all devices connect to a central switch/hub — most common.\n- **Bus**: all devices share a single cable.\n- **Ring**: devices connected in a circle.\n- **Mesh**: every device connects to every other — highly reliable.\n",
      },
      {
        title: "Electronic communications",
        type: "text",
        order: 3,
        content:
          "# Electronic Communications\n\n## Email\nEmail (electronic mail) sends messages over the internet.\n- **Protocols**: SMTP (sending), POP3/IMAP (receiving).\n- IMAP keeps emails on the server; POP3 downloads and may delete them.\n\n## Instant Messaging and VoIP\n- **IM** (Instant Messaging): real-time text (e.g., WhatsApp, Telegram).\n- **VoIP** (Voice over IP): voice/video calls over the internet (e.g., Zoom, Teams).\n\n## Social Implications of E-Communications\n- **Netiquette**: rules for polite online communication.\n  - Use professional language in emails.\n  - Don't type in ALL CAPS (it means shouting).\n  - Think before posting on social media.\n- **Cyberbullying**: using technology to harass or intimidate others.\n- **Spam**: unwanted bulk emails — use spam filters.\n- **Phishing**: fake emails tricking you into revealing personal information.\n\n## Data Transmission\n- **Bandwidth**: the amount of data that can be transmitted per second (measured in Mbps or Gbps).\n- **Latency**: the delay before data transfer begins.\n",
      },
    ],
    quiz: {
      title: "System Software and Networks Quiz",
      description:
        "Test your understanding of operating systems, utilities, and network fundamentals.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Name three functions of an operating system.",
          type: "short_answer",
          correctAnswer:
            "Process management, memory management, and file management.",
          explanation: "The OS manages all system resources.",
        },
        {
          questionText: "What is the purpose of a device driver?",
          type: "short_answer",
          correctAnswer:
            "To allow the operating system to communicate with a specific hardware device.",
          explanation: "Drivers act as translators between the OS and hardware.",
        },
        {
          questionText: "Which network type covers a single building?",
          type: "multiple_choice",
          options: ["LAN", "WAN", "MAN", "PAN"],
          correctAnswer: "LAN",
          explanation: "A LAN (Local Area Network) covers a small area.",
        },
        {
          questionText:
            "Which email protocol keeps messages stored on the server?",
          type: "multiple_choice",
          options: ["IMAP", "POP3", "SMTP", "FTP"],
          correctAnswer: "IMAP",
          explanation: "IMAP synchronises and keeps emails on the server.",
        },
        {
          questionText:
            "What is the difference between a router and a switch?",
          type: "essay",
          correctAnswer:
            "A router directs data between different networks (e.g., from a LAN to the internet). A switch connects devices within the same local network (LAN) and forwards data to the correct device using MAC addresses.",
          explanation: "Routers work between networks; switches work within a network.",
        },
      ],
    },
  },
  {
    key: "it10-selection",
    title: "Selection and Boolean Logic",
    description:
      "Use IF, IF-ELSE, nested IF, and CASE statements in Delphi. Combine conditions using AND, OR, and NOT operators.",
    grade: 10,
    order: 6,
    capsTags: ["selection", "boolean", "if-else", "case"],
    lessons: [
      {
        title: "IF, IF-ELSE, and nested IF",
        type: "text",
        order: 1,
        content:
          "# Selection Statements\n\nSelection allows a program to make decisions based on conditions.\n\n## Simple IF\n```pascal\nif iAge >= 18 then\n  ShowMessage('You may vote.');\n```\n\n## IF-ELSE\n```pascal\nif iMark >= 50 then\n  lblResult.Caption := 'Pass'\nelse\n  lblResult.Caption := 'Fail';\n```\n\n## Nested IF (IF within IF)\n```pascal\nif iMark >= 80 then\n  sSymbol := 'A'\nelse if iMark >= 70 then\n  sSymbol := 'B'\nelse if iMark >= 60 then\n  sSymbol := 'C'\nelse if iMark >= 50 then\n  sSymbol := 'D'\nelse\n  sSymbol := 'F';\n```\n\n## Comparison Operators\n| Operator | Meaning |\n|----------|----------|\n| = | Equal to |\n| <> | Not equal to |\n| > | Greater than |\n| < | Less than |\n| >= | Greater than or equal |\n| <= | Less than or equal |\n\n**Important**: In Delphi, use `:=` for assignment and `=` for comparison.\n",
      },
      {
        title: "Boolean logic: AND, OR, NOT",
        type: "text",
        order: 2,
        content:
          "# Boolean Logic\n\nBoolean expressions evaluate to **True** or **False**.\n\n## Logical Operators\n| Operator | Meaning | Example |\n|----------|---------|----------|\n| AND | Both must be true | (x > 0) AND (x < 100) |\n| OR | At least one true | (day = 'Sat') OR (day = 'Sun') |\n| NOT | Reverses the value | NOT (x = 0) |\n\n## Example: Check if a number is between 1 and 10\n```pascal\nif (iNum >= 1) AND (iNum <= 10) then\n  lblResult.Caption := 'In range'\nelse\n  lblResult.Caption := 'Out of range';\n```\n\n## Example: Weekend check\n```pascal\nif (sDay = 'Saturday') OR (sDay = 'Sunday') then\n  lblResult.Caption := 'Weekend!'\nelse\n  lblResult.Caption := 'Weekday';\n```\n\n## Truth Tables\n| A | B | A AND B | A OR B |\n|---|---|---------|--------|\n| T | T | T | T |\n| T | F | F | T |\n| F | T | F | T |\n| F | F | F | F |\n",
      },
      {
        title: "CASE statements and GUI selection",
        type: "text",
        order: 3,
        content:
          "# CASE Statements\n\nCASE provides a clean way to select among many options based on a single value.\n\n```pascal\ncase rgShapes.ItemIndex of\n  0: shpDisplay.Shape := stCircle;\n  1: shpDisplay.Shape := stRectangle;\n  2: shpDisplay.Shape := stSquare;\nelse\n  ShowMessage('Please select a shape.');\nend;\n```\n\n## When to Use CASE vs IF\n- Use **CASE** when testing one variable against multiple specific values.\n- Use **IF** when conditions involve ranges or complex Boolean expressions.\n\n## GUI Selection Components\n- **TRadioGroup**: lets the user pick one option. Use `ItemIndex` (0-based) to check which was selected.\n- **TComboBox**: drop-down list. Use `.Text` or `.ItemIndex`.\n- **TCheckBox**: use `.Checked` (Boolean True/False).\n\n## Example: Color selector\n```pascal\nprocedure TfrmMain.btnApplyClick(Sender: TObject);\nbegin\n  case cmbColor.ItemIndex of\n    0: pnlDisplay.Color := clRed;\n    1: pnlDisplay.Color := clBlue;\n    2: pnlDisplay.Color := clGreen;\n  end;\nend;\n```\n",
      },
    ],
    quiz: {
      title: "Selection and Boolean Logic Quiz",
      description: "Test your understanding of IF, CASE, and Boolean operators.",
      difficulty: "easy",
      questions: [
        {
          questionText:
            "Which Delphi operator checks if two values are equal?",
          type: "multiple_choice",
          options: ["=", ":=", "==", "<>"],
          correctAnswer: "=",
          explanation:
            "In Delphi, = is the equality comparison operator. := is assignment.",
        },
        {
          questionText:
            "Write a condition to check if a mark is between 40 and 60 inclusive.",
          type: "short_answer",
          correctAnswer: "(iMark >= 40) AND (iMark <= 60)",
          explanation: "Use AND to combine two range checks.",
        },
        {
          questionText:
            "What does the expression (True AND False) evaluate to?",
          type: "multiple_choice",
          options: ["False", "True", "Error", "Null"],
          correctAnswer: "False",
          explanation: "AND requires both operands to be True.",
        },
        {
          questionText: "When should you use CASE instead of IF?",
          type: "short_answer",
          correctAnswer:
            "When testing one variable against multiple specific values.",
          explanation:
            "CASE is cleaner for multi-value checks on a single variable.",
        },
        {
          questionText:
            "Which property of a TRadioGroup tells you which option was selected?",
          type: "multiple_choice",
          options: ["ItemIndex", "Text", "Caption", "Checked"],
          correctAnswer: "ItemIndex",
          explanation: "ItemIndex is a 0-based integer indicating the selected radio button.",
        },
        {
          questionText:
            "Write an IF-ELSE statement to display 'Pass' if mark >= 50 or 'Fail' otherwise.",
          type: "essay",
          correctAnswer:
            "if iMark >= 50 then\n  lblResult.Caption := 'Pass'\nelse\n  lblResult.Caption := 'Fail';",
          explanation: "A basic IF-ELSE pattern for pass/fail logic.",
        },
      ],
    },
  },
  {
    key: "it10-strings-intro",
    title: "Introduction to Strings",
    description:
      "Learn basic string operations in Delphi: Length, Copy, Pos, concatenation, and character access.",
    grade: 10,
    order: 7,
    capsTags: ["strings", "functions", "manipulation"],
    lessons: [
      {
        title: "String basics and built-in functions",
        type: "text",
        order: 1,
        content:
          "# Strings in Delphi\n\nA **string** is a sequence of characters. In Delphi, strings are **1-based** — the first character is at index 1.\n\n## Declaring Strings\n```pascal\nvar\n  sName: String;\n  sChar: Char;  // single character\n```\n\n## String Concatenation\nUse `+` to join strings:\n```pascal\nsFullName := sFirst + ' ' + sLast;\n```\n\n## Key String Functions\n| Function | Purpose | Example |\n|----------|---------|----------|\n| Length(s) | Returns number of characters | Length('Hello') = 5 |\n| Copy(s, start, count) | Extracts a substring | Copy('Hello', 1, 3) = 'Hel' |\n| Pos(sub, s) | Finds position of substring | Pos('lo', 'Hello') = 4 |\n| UpperCase(s) | Converts to uppercase | UpperCase('hi') = 'HI' |\n| LowerCase(s) | Converts to lowercase | LowerCase('HI') = 'hi' |\n| Trim(s) | Removes leading/trailing spaces | Trim('  hi  ') = 'hi' |\n\n## Accessing Individual Characters\n```pascal\nsFirst := sName[1];   // first character\nsLast := sName[Length(sName)]; // last character\n```\n",
      },
      {
        title: "String manipulation examples",
        type: "text",
        order: 2,
        content:
          "# String Manipulation\n\n## Counting Characters\nCount how many vowels are in a string:\n```pascal\nvar\n  iCount, i: Integer;\nbegin\n  iCount := 0;\n  for i := 1 to Length(sWord) do\n    if UpCase(sWord[i]) in ['A','E','I','O','U'] then\n      Inc(iCount);\n  lblResult.Caption := IntToStr(iCount) + ' vowels';\nend;\n```\n\n## Reversing a String\n```pascal\nvar\n  sReversed: String;\n  i: Integer;\nbegin\n  sReversed := '';\n  for i := Length(sWord) downto 1 do\n    sReversed := sReversed + sWord[i];\nend;\n```\n\n## Insert and Delete\n- `Insert(source, target, position)` — inserts source into target at position.\n- `Delete(s, start, count)` — removes characters from s.\n\n```pascal\nvar s: String;\ns := 'Hllo';\nInsert('e', s, 2);  // s = 'Hello'\nDelete(s, 1, 1);    // s = 'ello'\n```\n",
      },
    ],
    quiz: {
      title: "Introduction to Strings Quiz",
      description: "Test your understanding of string functions and manipulation.",
      difficulty: "easy",
      questions: [
        {
          questionText: "What is the index of the first character in a Delphi string?",
          type: "short_answer",
          correctAnswer: "1",
          explanation: "Delphi strings are 1-based.",
        },
        {
          questionText: "What does Length('Delphi') return?",
          type: "short_answer",
          correctAnswer: "6",
          explanation: "The string 'Delphi' has 6 characters.",
        },
        {
          questionText: "What does Copy('Programming', 4, 4) return?",
          type: "multiple_choice",
          options: ["gram", "gra", "ogra", "ramm"],
          correctAnswer: "gram",
          explanation: "Copy starts at position 4 ('g') and takes 4 characters: 'gram'.",
        },
        {
          questionText: "Which function finds the position of a substring within a string?",
          type: "multiple_choice",
          options: ["Pos", "Copy", "Length", "Insert"],
          correctAnswer: "Pos",
          explanation: "Pos returns the starting position of a substring.",
        },
        {
          questionText: "Write code to reverse the string stored in variable sWord.",
          type: "essay",
          correctAnswer:
            "sReversed := '';\nfor i := Length(sWord) downto 1 do\n  sReversed := sReversed + sWord[i];",
          explanation: "Loop from the last character to the first, building the reversed string.",
        },
      ],
    },
  },
  // ─── TERM 3 ───────────────────────────────────────────────
  {
    key: "it10-computer-management",
    title: "Computer Management and Security",
    description:
      "Manage files and folders, perform housekeeping tasks, and understand basic computer security concepts.",
    grade: 10,
    order: 8,
    capsTags: ["management", "files", "security", "housekeeping"],
    lessons: [
      {
        title: "File and folder management",
        type: "text",
        order: 1,
        content:
          "# File and Folder Management\n\n## Organizing Files\n- Use a clear folder structure: e.g., `Documents/IT/Grade10/Term3/`.\n- Give files meaningful names (avoid `Document1.txt`).\n- Use standard extensions: `.txt`, `.pas`, `.dpr`, `.pdf`, `.docx`.\n\n## File Properties\n- **Filename**: the name you give the file.\n- **Extension**: indicates the file type (e.g., `.pdf`, `.exe`, `.pas`).\n- **Size**: measured in bytes, KB, MB, GB.\n- **Date modified**: last time the file was changed.\n\n## File Operations\n- **Copy**: duplicate a file to another location.\n- **Move**: transfer a file (removes from original).\n- **Rename**: change the filename.\n- **Delete**: move to Recycle Bin.\n- **Compress/ZIP**: reduce folder size for sharing.\n\n## Housekeeping\n- Run **disk cleanup** regularly to remove temp files.\n- **Defragment** HDDs (not SSDs) for better performance.\n- Empty the **Recycle Bin** to recover space.\n- Uninstall unused programs.\n",
      },
      {
        title: "Computer security basics",
        type: "text",
        order: 2,
        content:
          "# Computer Security\n\n## Types of Threats\n| Threat | Description |\n|--------|-------------|\n| Virus | Attaches to files, spreads when executed |\n| Worm | Self-replicating, spreads over networks |\n| Trojan | Disguised as legitimate software |\n| Spyware | Secretly collects user data |\n| Ransomware | Encrypts files, demands payment |\n| Adware | Displays unwanted advertisements |\n\n## Protection Methods\n1. **Antivirus software**: install and keep updated.\n2. **Firewall**: monitors and controls network traffic.\n3. **Strong passwords**: use uppercase, lowercase, numbers, symbols; minimum 8 characters.\n4. **Regular updates**: keep OS and software patched.\n5. **Backups**: 3-2-1 rule (3 copies, 2 different media, 1 offsite).\n6. **Be cautious**: don't click suspicious links or download unknown attachments.\n\n## POPIA (Protection of Personal Information Act)\nSouth Africa's POPIA protects personal data:\n- Organizations must get consent before collecting personal info.\n- Data must be stored securely and not kept longer than necessary.\n- Individuals have the right to access and correct their personal info.\n",
      },
    ],
    quiz: {
      title: "Computer Management and Security Quiz",
      description: "Test your knowledge of file management, housekeeping, and security.",
      difficulty: "easy",
      questions: [
        {
          questionText: "What is the purpose of a firewall?",
          type: "short_answer",
          correctAnswer: "To monitor and control incoming and outgoing network traffic.",
          explanation: "Firewalls are a key security measure.",
        },
        {
          questionText: "Which type of malware disguises itself as legitimate software?",
          type: "multiple_choice",
          options: ["Trojan", "Worm", "Adware", "Virus"],
          correctAnswer: "Trojan",
          explanation: "A Trojan appears useful but contains hidden malicious code.",
        },
        {
          questionText: "What does POPIA stand for?",
          type: "short_answer",
          correctAnswer: "Protection of Personal Information Act",
          explanation: "POPIA is South Africa's data protection law.",
        },
        {
          questionText: "Why should you NOT defragment an SSD?",
          type: "multiple_choice",
          options: [
            "SSDs have no moving parts and defragmentation reduces their lifespan",
            "SSDs are too small to defragment",
            "SSDs automatically defragment themselves",
            "Defragmentation only works on optical drives",
          ],
          correctAnswer: "SSDs have no moving parts and defragmentation reduces their lifespan",
          explanation: "SSDs use flash memory; defragmentation causes unnecessary writes.",
        },
        {
          questionText: "Explain the 3-2-1 backup rule.",
          type: "essay",
          correctAnswer:
            "Keep 3 copies of your data on 2 different types of storage media with 1 copy stored offsite (e.g., cloud or different location). This protects against hardware failure, theft, and disasters.",
          explanation: "The 3-2-1 rule is a best practice for data backup.",
        },
      ],
    },
  },
  {
    key: "it10-internet-www",
    title: "Internet and the World Wide Web",
    description:
      "Understand how the internet works, the difference between the internet and WWW, web browsers, URLs, and search techniques.",
    grade: 10,
    order: 9,
    capsTags: ["internet", "www", "browsers", "search"],
    lessons: [
      {
        title: "Internet fundamentals",
        type: "text",
        order: 1,
        content:
          "# The Internet\n\nThe **internet** is a global network of interconnected networks that communicate using standard protocols.\n\n## Internet vs WWW\n- **Internet**: the physical infrastructure (cables, routers, servers).\n- **WWW (World Wide Web)**: a service that runs on the internet — web pages accessed via browsers.\n\n## How the Internet Works\n1. You type a URL in your browser.\n2. A **DNS server** translates the domain name to an IP address.\n3. Your browser sends a request to the web server at that IP address.\n4. The server sends back the web page (HTML, CSS, JavaScript).\n5. Your browser renders the page.\n\n## Key Protocols\n| Protocol | Purpose |\n|----------|----------|\n| HTTP/HTTPS | Web page transfer (HTTPS is encrypted) |\n| FTP | File transfer |\n| SMTP | Sending email |\n| POP3/IMAP | Receiving email |\n| TCP/IP | Core internet communication |\n| DNS | Domain name to IP address translation |\n\n## Internet Connections in South Africa\n- **ADSL**: over telephone lines (older, slower).\n- **Fibre**: fastest, uses light through fibre-optic cables.\n- **Mobile data (3G/4G/5G)**: wireless via cell towers.\n- **Satellite**: for remote areas.\n",
      },
      {
        title: "Web browsers and searching effectively",
        type: "text",
        order: 2,
        content:
          '# Web Browsers and Searching\n\n## Web Browsers\nA **web browser** displays web pages. Examples: Chrome, Firefox, Edge, Safari.\n\n### Browser Features\n- **Tabs**: open multiple pages.\n- **Bookmarks/Favourites**: save frequently visited pages.\n- **History**: record of visited pages.\n- **Downloads manager**: track downloaded files.\n- **Extensions/Add-ons**: add functionality (ad blockers, password managers).\n\n## URLs\nA **URL** (Uniform Resource Locator) is a web address:\n```\nhttps://www.education.gov.za/Curriculum/NCS.aspx\n  ^       ^                        ^           ^\nprotocol  domain                   path        page\n```\n\n## Search Techniques\nUse these to get better search results:\n- **Quotes**: "exact phrase" — finds the exact words in order.\n- **Minus sign**: python -snake — excludes results about snakes.\n- **Site search**: site:edu.za climate — searches only .edu.za websites.\n- **File type**: filetype:pdf IT CAPS — finds only PDF files.\n\n## Evaluating Online Sources\n- Check the **author and date**.\n- Prefer **.gov.za**, **.edu**, **.ac.za** for reliable information.\n- Cross-reference with multiple sources.\n- Be skeptical of unsourced claims.\n',
      },
    ],
    quiz: {
      title: "Internet and WWW Quiz",
      description: "Test your knowledge of the internet, protocols, and web browsing.",
      difficulty: "easy",
      questions: [
        {
          questionText: "What is the difference between the internet and the WWW?",
          type: "essay",
          correctAnswer:
            "The internet is the global physical network infrastructure (cables, routers, servers). The WWW is a service that runs on the internet, consisting of web pages accessed through browsers using HTTP/HTTPS.",
          explanation: "The WWW is one of many services on the internet.",
        },
        {
          questionText: "What does DNS stand for?",
          type: "short_answer",
          correctAnswer: "Domain Name System",
          explanation: "DNS translates domain names into IP addresses.",
        },
        {
          questionText: "Which protocol ensures encrypted web page transfer?",
          type: "multiple_choice",
          options: ["HTTPS", "HTTP", "FTP", "SMTP"],
          correctAnswer: "HTTPS",
          explanation: "HTTPS uses SSL/TLS encryption for secure web browsing.",
        },
        {
          questionText: "Which internet connection type is the fastest?",
          type: "multiple_choice",
          options: ["Fibre", "ADSL", "3G", "Satellite"],
          correctAnswer: "Fibre",
          explanation: "Fibre-optic uses light signals for the highest speeds.",
        },
        {
          questionText:
            "What search technique would you use to find only .pdf files about CAPS?",
          type: "short_answer",
          correctAnswer: "filetype:pdf CAPS",
          explanation: "The filetype: operator limits results to a specific file format.",
        },
      ],
    },
  },
  {
    key: "it10-loops",
    title: "Loops: FOR, WHILE, and REPEAT",
    description:
      "Use repetition structures in Delphi to perform tasks multiple times. Learn FOR, WHILE, and REPEAT-UNTIL loops with counters and accumulators.",
    grade: 10,
    order: 10,
    capsTags: ["loops", "for", "while", "repeat", "accumulators"],
    lessons: [
      {
        title: "FOR loops",
        type: "text",
        order: 1,
        content:
          "# FOR Loops\n\nA **FOR loop** repeats a fixed number of times.\n\n## Syntax\n```pascal\nfor variable := startValue to endValue do\nbegin\n  // statements\nend;\n```\n\n## Counting Up\n```pascal\nfor i := 1 to 5 do\n  memOutput.Lines.Add(IntToStr(i));\n// Output: 1, 2, 3, 4, 5\n```\n\n## Counting Down\n```pascal\nfor i := 10 downto 1 do\n  memOutput.Lines.Add(IntToStr(i));\n// Output: 10, 9, 8, ... 1\n```\n\n## Using a Counter\nA **counter** tracks how many times something occurs:\n```pascal\nvar iCount: Integer;\niCount := 0;\nfor i := 1 to Length(sWord) do\n  if sWord[i] = 'a' then\n    Inc(iCount);\nlblResult.Caption := IntToStr(iCount) + ' a''s found';\n```\n\n## Using an Accumulator\nAn **accumulator** builds a running total:\n```pascal\nvar iTotal: Integer;\niTotal := 0;\nfor i := 1 to 10 do\n  iTotal := iTotal + i;\n// iTotal = 55\n```\n",
      },
      {
        title: "WHILE and REPEAT-UNTIL loops",
        type: "text",
        order: 2,
        content:
          "# WHILE and REPEAT Loops\n\n## WHILE Loop\nRepeats **while** a condition is true. The condition is tested **before** each iteration.\n\n```pascal\nvar iNum: Integer;\niNum := 1;\nwhile iNum <= 10 do\nbegin\n  memOutput.Lines.Add(IntToStr(iNum));\n  Inc(iNum);\nend;\n```\n\n**Important**: If the condition is false at the start, the loop body never executes.\n\n## REPEAT-UNTIL Loop\nRepeats **until** a condition becomes true. The body executes **at least once** because the test is at the end.\n\n```pascal\nvar sPassword: String;\nrepeat\n  sPassword := InputBox('Login', 'Enter password:', '');\nuntil sPassword = 'secret123';\nShowMessage('Access granted!');\n```\n\n## Comparison\n| Feature | FOR | WHILE | REPEAT-UNTIL |\n|---------|-----|-------|--------------|\n| Times known? | Yes | No | No |\n| Test position | N/A | Before | After |\n| Min executions | 0 or known | 0 | 1 |\n| Use when... | Counting | Condition-controlled | Must run at least once |\n\n## Avoiding Infinite Loops\n- Always ensure the condition will eventually become false.\n- Make sure the loop variable changes inside the loop.\n",
      },
      {
        title: "Building patterns with loops",
        type: "text",
        order: 3,
        content:
          "# Pattern Building with Loops\n\n## String Patterns\nBuild patterns by accumulating characters in a string:\n```pascal\nvar sLine: String;\nvar i, j: Integer;\nfor i := 1 to 5 do\nbegin\n  sLine := '';\n  for j := 1 to i do\n    sLine := sLine + '*';\n  memOutput.Lines.Add(sLine);\nend;\n```\n**Output:**\n```\n*\n**\n***\n****\n*****\n```\n\n## Number Patterns\n```pascal\nfor i := 1 to 5 do\nbegin\n  sLine := '';\n  for j := 1 to i do\n    sLine := sLine + IntToStr(i);\n  memOutput.Lines.Add(sLine);\nend;\n```\n**Output:**\n```\n1\n22\n333\n4444\n55555\n```\n\n## Practical Application\nPatterns test your understanding of:\n- Nested loops (outer = rows, inner = columns).\n- String building with concatenation.\n- How loop variables relate to the pattern.\n\nThese are common exam questions in CAPS IT Paper 1.\n",
      },
    ],
    quiz: {
      title: "Loops Quiz",
      description: "Test your understanding of FOR, WHILE, and REPEAT loops.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Which loop type always executes its body at least once?",
          type: "multiple_choice",
          options: ["REPEAT-UNTIL", "WHILE", "FOR", "CASE"],
          correctAnswer: "REPEAT-UNTIL",
          explanation: "REPEAT tests the condition after the body executes.",
        },
        {
          questionText: "Write a FOR loop to display numbers from 5 down to 1.",
          type: "short_answer",
          correctAnswer: "for i := 5 downto 1 do ...",
          explanation: "Use 'downto' for counting down.",
        },
        {
          questionText: "What is the value of iTotal after: iTotal := 0; for i := 1 to 4 do iTotal := iTotal + i;",
          type: "short_answer",
          correctAnswer: "10",
          explanation: "1 + 2 + 3 + 4 = 10.",
        },
        {
          questionText: "When should you use a WHILE loop instead of a FOR loop?",
          type: "short_answer",
          correctAnswer: "When you don't know in advance how many times the loop will repeat.",
          explanation: "FOR loops are for known counts; WHILE loops are condition-controlled.",
        },
        {
          questionText: "What causes an infinite loop?",
          type: "multiple_choice",
          options: [
            "The condition never becomes false",
            "Using Inc inside the loop",
            "A FOR loop counting up",
            "Having too many variables",
          ],
          correctAnswer: "The condition never becomes false",
          explanation: "If the exit condition is never met, the loop runs forever.",
        },
        {
          questionText: "Explain how nested loops are used to build a star triangle pattern.",
          type: "essay",
          correctAnswer:
            "The outer loop controls the number of rows (e.g., 1 to 5). For each row i, the inner loop runs i times, appending a star to a string. After the inner loop, the accumulated line is displayed. This creates a triangle shape with increasing stars per row.",
          explanation: "Nested loops are a key pattern-building technique in CAPS IT.",
        },
      ],
    },
  },
  // ─── TERM 4 ───────────────────────────────────────────────
  {
    key: "it10-internet-services",
    title: "Internet Services and Online Applications",
    description:
      "Explore internet services including cloud computing, web applications, e-commerce, and online collaboration tools.",
    grade: 10,
    order: 11,
    capsTags: ["internet-services", "cloud", "e-commerce", "web-apps"],
    lessons: [
      {
        title: "Cloud computing and web applications",
        type: "text",
        order: 1,
        content:
          "# Cloud Computing\n\n**Cloud computing** provides computing services (storage, processing, software) over the internet.\n\n## Types of Cloud Services\n| Service | Description | Examples |\n|---------|-------------|----------|\n| SaaS | Software as a Service | Google Docs, Office 365 |\n| PaaS | Platform as a Service | Google App Engine |\n| IaaS | Infrastructure as a Service | AWS, Azure |\n\n## Cloud Storage\nStore files online and access them from anywhere:\n- Google Drive, OneDrive, Dropbox, iCloud.\n\n### Advantages\n- Access files from any device with internet.\n- Automatic backups.\n- Easy sharing and collaboration.\n\n### Disadvantages\n- Requires internet connection.\n- Privacy concerns — data stored on third-party servers.\n- Ongoing subscription costs.\n\n## Web Applications\nApps that run in a web browser (no installation needed):\n- Gmail, Google Sheets, Canva, Facebook.\n- Advantage: platform-independent, always up to date.\n",
      },
      {
        title: "E-commerce and online safety",
        type: "text",
        order: 2,
        content:
          "# E-Commerce and Online Safety\n\n## E-Commerce\n**E-commerce** is buying and selling goods/services online.\n\n### Types\n- **B2C** (Business to Consumer): online shops (Takealot, Amazon).\n- **B2B** (Business to Business): wholesale suppliers.\n- **C2C** (Consumer to Consumer): online marketplaces (Gumtree, Facebook Marketplace).\n\n### Advantages\n- Shop 24/7 from anywhere.\n- Compare prices easily.\n- Wider range of products.\n\n### Disadvantages\n- Cannot physically inspect items.\n- Risk of fraud.\n- Delivery delays.\n\n## Online Safety\n- Look for **HTTPS** and the padlock icon before entering personal data.\n- Use strong, unique passwords for each site.\n- Enable **two-factor authentication** (2FA) where possible.\n- Never share banking details via email.\n- Check website reviews before purchasing.\n\n## Online Collaboration Tools\n- **Google Workspace**: Docs, Sheets, Slides — real-time collaboration.\n- **Microsoft Teams**: chat, video meetings, file sharing.\n- **Zoom**: video conferencing.\n",
      },
    ],
    quiz: {
      title: "Internet Services Quiz",
      description: "Test your knowledge of cloud computing, e-commerce, and online safety.",
      difficulty: "easy",
      questions: [
        {
          questionText: "What does SaaS stand for?",
          type: "short_answer",
          correctAnswer: "Software as a Service",
          explanation: "SaaS delivers software over the internet (e.g., Google Docs).",
        },
        {
          questionText: "Give one advantage and one disadvantage of cloud storage.",
          type: "essay",
          correctAnswer:
            "Advantage: You can access files from any device with an internet connection. Disadvantage: You need internet access, and there are privacy concerns about data stored on third-party servers.",
          explanation: "Cloud storage has clear trade-offs between convenience and privacy.",
        },
        {
          questionText: "What type of e-commerce is Takealot?",
          type: "multiple_choice",
          options: ["B2C", "B2B", "C2C", "B2G"],
          correctAnswer: "B2C",
          explanation: "Takealot sells directly from business to consumer.",
        },
        {
          questionText: "What should you look for in the browser before entering banking details?",
          type: "multiple_choice",
          options: [
            "HTTPS and a padlock icon",
            "HTTP only",
            "A .com domain",
            "Pop-up advertisements",
          ],
          correctAnswer: "HTTPS and a padlock icon",
          explanation: "HTTPS uses encryption to protect your data in transit.",
        },
        {
          questionText: "What is two-factor authentication (2FA)?",
          type: "short_answer",
          correctAnswer:
            "A security method that requires two different forms of identification to access an account, such as a password and a code sent to your phone.",
          explanation: "2FA adds an extra layer of security beyond just a password.",
        },
      ],
    },
  },
  {
    key: "it10-text-files",
    title: "Text Files and File Handling",
    description:
      "Read from and write to text files in Delphi using AssignFile, Reset, Rewrite, Append, Readln, Writeln, and EOF.",
    grade: 10,
    order: 12,
    capsTags: ["files", "textfiles", "eof", "io"],
    lessons: [
      {
        title: "Reading from text files",
        type: "text",
        order: 1,
        content:
          "# Reading Text Files\n\nText files store data as lines of plain text. In Delphi, use the `TextFile` type to work with them.\n\n## Steps to Read a File\n```pascal\nvar\n  tFile: TextFile;\n  sLine: String;\nbegin\n  // 1. Check the file exists\n  if not FileExists('data.txt') then\n  begin\n    ShowMessage('File not found!');\n    Exit;\n  end;\n\n  // 2. Assign the file variable\n  AssignFile(tFile, 'data.txt');\n\n  // 3. Open for reading\n  Reset(tFile);\n\n  // 4. Read line by line until EOF\n  while not EOF(tFile) do\n  begin\n    Readln(tFile, sLine);\n    memOutput.Lines.Add(sLine);\n  end;\n\n  // 5. Close the file\n  CloseFile(tFile);\nend;\n```\n\n## Key Points\n- **AssignFile**: links a file variable to a physical file.\n- **Reset**: opens the file for reading.\n- **EOF**: returns True when the end of the file is reached.\n- **Readln**: reads one line.\n- **CloseFile**: always close the file when done.\n- **FileExists**: always check before opening.\n",
      },
      {
        title: "Writing to text files",
        type: "text",
        order: 2,
        content:
          "# Writing to Text Files\n\n## Creating a New File (Rewrite)\n`Rewrite` creates a new file or **overwrites** an existing file.\n\n```pascal\nvar\n  tFile: TextFile;\nbegin\n  AssignFile(tFile, 'output.txt');\n  Rewrite(tFile);  // creates or overwrites\n  Writeln(tFile, 'Line 1');\n  Writeln(tFile, 'Line 2');\n  CloseFile(tFile);\nend;\n```\n\n## Appending to an Existing File\n`Append` opens the file and adds data at the end without erasing existing content.\n\n```pascal\nAssignFile(tFile, 'output.txt');\nAppend(tFile);  // adds to end\nWriteln(tFile, 'New line added');\nCloseFile(tFile);\n```\n\n## When to Use Each\n| Command | Action |\n|---------|--------|\n| Reset | Open for reading |\n| Rewrite | Open for writing (creates/overwrites) |\n| Append | Open for writing at end (adds to file) |\n\n## Processing File Data\nExample: Calculate the average of numbers stored in a file.\n```pascal\nvar\n  tFile: TextFile;\n  iNum, iTotal, iCount: Integer;\nbegin\n  iTotal := 0;\n  iCount := 0;\n  AssignFile(tFile, 'numbers.txt');\n  Reset(tFile);\n  while not EOF(tFile) do\n  begin\n    Readln(tFile, iNum);\n    iTotal := iTotal + iNum;\n    Inc(iCount);\n  end;\n  CloseFile(tFile);\n  if iCount > 0 then\n    lblAvg.Caption := FormatFloat('0.00', iTotal / iCount);\nend;\n```\n",
      },
    ],
    quiz: {
      title: "Text Files Quiz",
      description: "Test your knowledge of reading from and writing to text files in Delphi.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Which command opens a text file for reading?",
          type: "multiple_choice",
          options: ["Reset", "Rewrite", "Append", "CloseFile"],
          correctAnswer: "Reset",
          explanation: "Reset opens an existing file for reading.",
        },
        {
          questionText: "What does EOF stand for?",
          type: "short_answer",
          correctAnswer: "End of File",
          explanation: "EOF returns True when there is no more data to read.",
        },
        {
          questionText: "What is the difference between Rewrite and Append?",
          type: "essay",
          correctAnswer:
            "Rewrite creates a new file or overwrites an existing one, erasing all previous content. Append opens an existing file and adds new data at the end, preserving existing content.",
          explanation: "Rewrite erases; Append adds to the end.",
        },
        {
          questionText: "Why should you always call CloseFile after working with a file?",
          type: "short_answer",
          correctAnswer:
            "To release the file handle and ensure all data is written to disk properly.",
          explanation: "Not closing files can lead to data loss or corruption.",
        },
        {
          questionText: "Why should you check FileExists before opening a file for reading?",
          type: "multiple_choice",
          options: [
            "To prevent a runtime error if the file does not exist",
            "To make the file read faster",
            "To count the number of lines",
            "To check the file extension",
          ],
          correctAnswer: "To prevent a runtime error if the file does not exist",
          explanation: "Calling Reset on a non-existent file causes a runtime error.",
        },
      ],
    },
  },
];
