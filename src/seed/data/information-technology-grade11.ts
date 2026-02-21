import type { ModuleSeed } from "../types.js";

/**
 * CAPS-aligned Information Technology Grade 11 Modules
 *
 * Based on the IT CAPS 2024 Section 3 document.
 * Grade 11 builds on Grade 10 with more advanced hardware, networking,
 * database management, arrays, sorting/searching, and the PAT project.
 *
 * Term 1: Advanced hardware, software, networks, security, arrays, search/sort
 * Term 2: E-communications, mobile tech, protocols, databases, text files, user-defined methods, PAT
 * Term 3: Database design concepts, social implications, database programming, PAT
 * Term 4: Internet evolution, IoT, big data, internet services, PAT finalization
 */

export const grade11Modules: ModuleSeed[] = [
  // ─── TERM 1 ───────────────────────────────────────────────
  {
    key: "it11-advanced-hardware",
    title: "Advanced Hardware Concepts",
    description:
      "Explore the motherboard, CPU architecture, memory hierarchy, and performance factors that affect computer speed.",
    grade: 11,
    order: 1,
    capsTags: ["hardware", "cpu", "motherboard", "memory", "performance"],
    lessons: [
      {
        title: "The motherboard and CPU",
        type: "text",
        order: 1,
        content:
          "# Motherboard and CPU\n\n## The Motherboard\nThe **motherboard** is the main circuit board connecting all components.\n\n### Key Components on the Motherboard\n- **CPU socket**: holds the processor.\n- **RAM slots**: for memory modules (DIMM).\n- **Expansion slots**: PCI, PCIe for graphics/sound/network cards.\n- **Chipset**: manages data flow between CPU, memory, and peripherals.\n- **BIOS/UEFI chip**: firmware that starts the boot process.\n- **CMOS battery**: keeps BIOS settings when power is off.\n- **Connectors**: SATA (storage), USB headers, power connectors, front panel.\n\n## The CPU (Central Processing Unit)\nThe CPU executes instructions in a cycle called **Fetch-Decode-Execute**:\n1. **Fetch**: retrieve the next instruction from memory.\n2. **Decode**: interpret what the instruction means.\n3. **Execute**: carry out the instruction.\n\n### CPU Performance Factors\n| Factor | Description |\n|--------|------------|\n| Clock speed | Measured in GHz — how many cycles per second |\n| Number of cores | More cores = more tasks processed simultaneously |\n| Cache memory | Small, fast memory inside the CPU (L1, L2, L3) |\n| Word size | 32-bit vs 64-bit — amount of data processed per cycle |\n| Bus speed | Speed of data transfer between components |\n",
      },
      {
        title: "Memory hierarchy and storage technologies",
        type: "text",
        order: 2,
        content:
          "# Memory Hierarchy\n\nMemory is arranged in a hierarchy by speed and cost:\n\n```\nRegisters    ← fastest, smallest, most expensive\nCache (L1, L2, L3)\nRAM\nSSD / HDD    ← slowest, largest, cheapest\n```\n\n## RAM Types\n| Type | Description |\n|------|------------|\n| SRAM | Static RAM — used for cache, very fast, expensive |\n| DRAM | Dynamic RAM — used for main memory, cheaper |\n| DDR4 / DDR5 | Double Data Rate — current standard for desktop/laptop RAM |\n\n## ROM vs RAM\n| Feature | ROM | RAM |\n|---------|-----|-----|\n| Volatile? | No | Yes |\n| Purpose | BIOS, firmware | Working memory |\n| Speed | Slower | Faster |\n| Writable? | Read-only (mostly) | Read/write |\n\n## Virtual Memory\nWhen RAM is full, the OS uses part of the hard drive as **virtual memory** (swap space). This is much slower than actual RAM.\n\n## How to Improve Performance\n- Add more RAM.\n- Upgrade to SSD.\n- Use a CPU with higher clock speed or more cores.\n- Close unnecessary background programs.\n- Keep the OS and drivers updated.\n",
      },
    ],
    quiz: {
      title: "Advanced Hardware Quiz",
      description: "Test your understanding of CPU, memory, and performance concepts.",
      difficulty: "medium",
      questions: [
        {
          questionText: "List the three steps of the CPU instruction cycle.",
          type: "short_answer",
          correctAnswer: "Fetch, Decode, Execute",
          explanation: "The Fetch-Decode-Execute cycle is the basic operation of any CPU.",
        },
        {
          questionText: "Which type of memory is the fastest in the memory hierarchy?",
          type: "multiple_choice",
          options: ["Registers", "Cache", "RAM", "SSD"],
          correctAnswer: "Registers",
          explanation: "Registers are inside the CPU and operate at CPU speed.",
        },
        {
          questionText: "What is the purpose of the CMOS battery on the motherboard?",
          type: "short_answer",
          correctAnswer: "To keep the BIOS/UEFI settings and real-time clock running when the computer is off.",
          explanation: "Without the CMOS battery, BIOS settings would be lost each time the computer is powered off.",
        },
        {
          questionText: "What is virtual memory?",
          type: "multiple_choice",
          options: [
            "Hard drive space used as extra RAM when physical RAM is full",
            "A type of cloud storage",
            "The cache inside the CPU",
            "Memory on a USB flash drive",
          ],
          correctAnswer: "Hard drive space used as extra RAM when physical RAM is full",
          explanation: "Virtual memory extends usable RAM but is much slower.",
        },
        {
          questionText: "Explain two ways to improve computer performance.",
          type: "essay",
          correctAnswer:
            "1. Add more RAM to allow more programs to run simultaneously without using slow virtual memory. 2. Upgrade from an HDD to an SSD for faster read/write speeds, which improves boot time and program loading.",
          explanation: "RAM and SSD upgrades are the most impactful performance improvements.",
        },
      ],
    },
  },
  {
    key: "it11-software-security",
    title: "Software and Network Security",
    description:
      "Understand software categories, licensing models, and advanced security threats including network attacks, encryption, and protection strategies.",
    grade: 11,
    order: 2,
    capsTags: ["software", "licensing", "security", "encryption", "threats"],
    lessons: [
      {
        title: "Software categories and licensing",
        type: "text",
        order: 1,
        content:
          "# Software Categories\n\n## System Software\n- **Operating systems**: Windows, Linux, macOS.\n- **Utility software**: antivirus, backup, disk tools.\n- **Device drivers**: hardware-specific communication software.\n\n## Application Software\n- **Productivity**: MS Office, LibreOffice.\n- **Multimedia**: Photoshop, Audacity, VLC.\n- **Communication**: email clients, browsers.\n- **Development**: Delphi, VS Code, Python IDLE.\n\n## Software Licensing\n| License Type | Description |\n|-------------|------------|\n| Proprietary | Paid, closed source (Microsoft Office) |\n| Open Source | Free to view, modify, distribute (Linux, Firefox) |\n| Freeware | Free to use, but source code is closed (Skype) |\n| Shareware | Free trial, then requires payment |\n| Creative Commons | Author sets specific conditions for use |\n| Public Domain | No copyright restrictions |\n\n## Software Piracy\nIllegal copying or distribution of software. It is against the law in South Africa and harms developers.\n\n## EULA (End User License Agreement)\nA legal contract between software developer and user that specifies how the software may be used.\n",
      },
      {
        title: "Network security and threats",
        type: "text",
        order: 2,
        content:
          "# Network Security\n\n## Common Network Threats\n| Threat | Description |\n|--------|------------|\n| Man-in-the-Middle (MITM) | Attacker intercepts communication between two parties |\n| Denial of Service (DoS) | Overwhelms a server with requests to make it unavailable |\n| Packet sniffing | Capturing data packets traveling over a network |\n| SQL injection | Inserting malicious SQL into web forms to access databases |\n| Brute force | Trying every possible password combination |\n| Social engineering | Manipulating people into revealing confidential information |\n\n## Protection Strategies\n- **Firewalls**: filter incoming and outgoing network traffic.\n- **Encryption**: scrambles data so only authorized parties can read it.\n  - **Symmetric encryption**: same key to encrypt and decrypt.\n  - **Asymmetric encryption**: public key encrypts, private key decrypts.\n- **SSL/TLS certificates**: secure website connections (HTTPS).\n- **VPN (Virtual Private Network)**: encrypts all internet traffic through a secure tunnel.\n- **Intrusion Detection Systems (IDS)**: monitors network for suspicious activity.\n\n## Authentication Methods\n- **Passwords**: something you know.\n- **Biometrics**: something you are (fingerprint, face recognition).\n- **Tokens/OTP**: something you have (SMS code, authenticator app).\n- **Multi-factor authentication (MFA)**: combines two or more methods.\n",
      },
    ],
    quiz: {
      title: "Software and Security Quiz",
      description: "Test your knowledge of software licensing and network security concepts.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the difference between open source and freeware?",
          type: "essay",
          correctAnswer:
            "Open source software provides the source code, allowing users to view, modify, and distribute it. Freeware is free to use but the source code is not available for modification.",
          explanation: "Open source = available source code; freeware = free but closed source.",
        },
        {
          questionText: "What type of attack overwhelms a server with requests?",
          type: "multiple_choice",
          options: ["DoS (Denial of Service)", "Phishing", "Brute force", "SQL injection"],
          correctAnswer: "DoS (Denial of Service)",
          explanation: "A DoS attack floods a server to make it unavailable.",
        },
        {
          questionText: "What is the difference between symmetric and asymmetric encryption?",
          type: "short_answer",
          correctAnswer:
            "Symmetric encryption uses the same key for encrypting and decrypting. Asymmetric encryption uses a public key to encrypt and a private key to decrypt.",
          explanation: "Asymmetric encryption is more secure for key exchange.",
        },
        {
          questionText: "What does VPN stand for?",
          type: "short_answer",
          correctAnswer: "Virtual Private Network",
          explanation: "A VPN encrypts internet traffic through a secure tunnel.",
        },
        {
          questionText: "Which authentication method uses fingerprint or face recognition?",
          type: "multiple_choice",
          options: ["Biometrics", "Password", "OTP", "Firewall"],
          correctAnswer: "Biometrics",
          explanation: "Biometrics use physical characteristics for identification.",
        },
      ],
    },
  },
  {
    key: "it11-arrays-search-sort",
    title: "Arrays, Searching, and Sorting",
    description:
      "Declare and use one-dimensional arrays. Implement linear search, binary search, bubble sort, and selection sort in Delphi.",
    grade: 11,
    order: 3,
    capsTags: ["arrays", "search", "sort", "linear-search", "bubble-sort"],
    lessons: [
      {
        title: "One-dimensional arrays",
        type: "text",
        order: 1,
        content:
          "# One-Dimensional Arrays\n\nAn **array** is a data structure that stores multiple values of the same type under one name.\n\n## Declaring Arrays in Delphi\n```pascal\nvar\n  arrNames: array[1..5] of String;\n  arrMarks: array[1..30] of Integer;\n  arrPrices: array[1..100] of Real;\n```\n\n## Accessing Elements\n```pascal\narrNames[1] := 'Alice';\narrMarks[3] := 85;\nlblResult.Caption := arrNames[1]; // Displays 'Alice'\n```\n\n## Populating from User Input\n```pascal\nfor i := 1 to 5 do\n  arrMarks[i] := StrToInt(InputBox('Input', 'Enter mark ' + IntToStr(i), ''));\n```\n\n## Common Array Operations\n```pascal\n// Find the total and average\niTotal := 0;\nfor i := 1 to iSize do\n  iTotal := iTotal + arrMarks[i];\nrAvg := iTotal / iSize;\n\n// Find the maximum\niMax := arrMarks[1];\nfor i := 2 to iSize do\n  if arrMarks[i] > iMax then\n    iMax := arrMarks[i];\n\n// Count values meeting a condition\niCount := 0;\nfor i := 1 to iSize do\n  if arrMarks[i] >= 50 then\n    Inc(iCount);\n```\n",
      },
      {
        title: "Searching: Linear and binary search",
        type: "text",
        order: 2,
        content:
          "# Searching Algorithms\n\n## Linear Search\nChecks each element one by one until the target is found or the end of the array is reached.\n\n```pascal\nfunction LinearSearch(arr: array of Integer; iSize, iTarget: Integer): Integer;\nvar i: Integer;\nbegin\n  Result := -1; // not found\n  for i := 0 to iSize - 1 do\n    if arr[i] = iTarget then\n    begin\n      Result := i;\n      Exit;\n    end;\nend;\n```\n\n**Time complexity**: O(n) — worst case checks every element.\n**Works on**: sorted or unsorted arrays.\n\n## Binary Search\nDivides the sorted array in half each step. Much faster for large, sorted arrays.\n\n```pascal\nfunction BinarySearch(arr: array of Integer; iSize, iTarget: Integer): Integer;\nvar iLow, iHigh, iMid: Integer;\nbegin\n  Result := -1;\n  iLow := 0;\n  iHigh := iSize - 1;\n  while iLow <= iHigh do\n  begin\n    iMid := (iLow + iHigh) div 2;\n    if arr[iMid] = iTarget then\n    begin\n      Result := iMid;\n      Exit;\n    end\n    else if arr[iMid] < iTarget then\n      iLow := iMid + 1\n    else\n      iHigh := iMid - 1;\n  end;\nend;\n```\n\n**Time complexity**: O(log n) — halves the data each time.\n**Requires**: the array must be sorted.\n",
      },
      {
        title: "Sorting: Bubble sort and selection sort",
        type: "text",
        order: 3,
        content:
          "# Sorting Algorithms\n\n## Bubble Sort\nRepeatedly compares adjacent elements and swaps them if out of order. Repeats passes until no swaps occur.\n\n```pascal\nprocedure BubbleSort(var arr: array of Integer; iSize: Integer);\nvar i, j, iTemp: Integer;\nbegin\n  for i := 0 to iSize - 2 do\n    for j := 0 to iSize - 2 - i do\n      if arr[j] > arr[j + 1] then\n      begin\n        iTemp := arr[j];\n        arr[j] := arr[j + 1];\n        arr[j + 1] := iTemp;\n      end;\nend;\n```\n\n## Selection Sort\nFinds the smallest element and places it at the front, then repeats for the remaining elements.\n\n```pascal\nprocedure SelectionSort(var arr: array of Integer; iSize: Integer);\nvar i, j, iMinIdx, iTemp: Integer;\nbegin\n  for i := 0 to iSize - 2 do\n  begin\n    iMinIdx := i;\n    for j := i + 1 to iSize - 1 do\n      if arr[j] < arr[iMinIdx] then\n        iMinIdx := j;\n    // Swap\n    iTemp := arr[i];\n    arr[i] := arr[iMinIdx];\n    arr[iMinIdx] := iTemp;\n  end;\nend;\n```\n\n## Comparison\n| Algorithm | Best Case | Worst Case | Stable? |\n|-----------|-----------|------------|----------|\n| Bubble Sort | O(n) | O(n^2) | Yes |\n| Selection Sort | O(n^2) | O(n^2) | No |\n\n**Stable**: a stable sort preserves the relative order of equal elements.\n",
      },
    ],
    quiz: {
      title: "Arrays, Search, and Sort Quiz",
      description: "Test your understanding of arrays, linear/binary search, and sorting algorithms.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the main advantage of binary search over linear search?",
          type: "short_answer",
          correctAnswer: "Binary search is much faster for large datasets because it halves the search space each step (O(log n) vs O(n)).",
          explanation: "Binary search is O(log n), while linear search is O(n).",
        },
        {
          questionText: "What prerequisite must be met before using binary search?",
          type: "multiple_choice",
          options: ["The array must be sorted", "The array must be unsorted", "The array must contain strings", "The array must have exactly 10 elements"],
          correctAnswer: "The array must be sorted",
          explanation: "Binary search relies on comparing the middle element and eliminating half the array.",
        },
        {
          questionText: "In bubble sort, what happens during each comparison?",
          type: "short_answer",
          correctAnswer: "Adjacent elements are compared and swapped if they are in the wrong order.",
          explanation: "Bubble sort repeatedly swaps adjacent out-of-order elements.",
        },
        {
          questionText: "Write code to find the maximum value in an array arrNums[1..10].",
          type: "essay",
          correctAnswer:
            "iMax := arrNums[1];\nfor i := 2 to 10 do\n  if arrNums[i] > iMax then\n    iMax := arrNums[i];",
          explanation: "Start with the first element as max, then compare each subsequent element.",
        },
        {
          questionText: "How many comparisons does linear search make in the worst case for an array of 100 elements?",
          type: "multiple_choice",
          options: ["100", "50", "10", "7"],
          correctAnswer: "100",
          explanation: "Linear search checks every element in the worst case: O(n) = 100.",
        },
      ],
    },
  },
  {
    key: "it11-string-date-handling",
    title: "Strings, Dates, and Type Conversion",
    description:
      "Advanced string manipulation, date handling with FormatDateTime, and robust type conversion techniques in Delphi.",
    grade: 11,
    order: 4,
    capsTags: ["strings", "dates", "conversion", "formatting"],
    lessons: [
      {
        title: "Advanced string manipulation",
        type: "text",
        order: 1,
        content:
          "# Advanced String Manipulation\n\n## Review: Key String Functions\n| Function | Purpose |\n|----------|----------|\n| Length(s) | Number of characters |\n| Copy(s, start, count) | Extract substring |\n| Pos(sub, s) | Find substring position |\n| Delete(s, start, count) | Remove characters |\n| Insert(src, target, pos) | Insert characters |\n| UpperCase(s) / LowerCase(s) | Change case |\n| Trim(s) | Remove spaces |\n| StringReplace(s, old, new, [rfReplaceAll]) | Replace text |\n\n## Extracting Words from a String\n```pascal\n// Split a sentence into words using a space delimiter\nvar\n  sSentence, sWord: String;\n  iPos: Integer;\nbegin\n  sSentence := 'Hello World Delphi';\n  while Pos(' ', sSentence) > 0 do\n  begin\n    iPos := Pos(' ', sSentence);\n    sWord := Copy(sSentence, 1, iPos - 1);\n    memOutput.Lines.Add(sWord);\n    Delete(sSentence, 1, iPos);\n  end;\n  memOutput.Lines.Add(sSentence); // last word\nend;\n```\n\n## Counting Specific Characters\n```pascal\nfunction CountChar(s: String; c: Char): Integer;\nvar i: Integer;\nbegin\n  Result := 0;\n  for i := 1 to Length(s) do\n    if s[i] = c then\n      Inc(Result);\nend;\n```\n\n## Checking for Palindromes\n```pascal\nfunction IsPalindrome(s: String): Boolean;\nvar i: Integer;\nbegin\n  s := UpperCase(s);\n  Result := True;\n  for i := 1 to Length(s) div 2 do\n    if s[i] <> s[Length(s) - i + 1] then\n    begin\n      Result := False;\n      Exit;\n    end;\nend;\n```\n",
      },
      {
        title: "Date handling and formatting",
        type: "text",
        order: 2,
        content:
          "# Date Handling in Delphi\n\n## Date and Time Functions\n| Function | Returns |\n|----------|----------|\n| Now | Current date and time |\n| Date | Current date only |\n| Time | Current time only |\n| DayOfWeek(d) | Day number (1=Sunday) |\n| EncodeDate(y, m, d) | Creates a TDateTime |\n| DecodeDate(d, y, m, d) | Extracts year, month, day |\n| DaysBetween(d1, d2) | Days between two dates |\n\n## FormatDateTime\nFormatDateTime converts a date to a formatted string:\n```pascal\nlblDate.Caption := FormatDateTime('dd/mm/yyyy', Now);\n// Output: 15/02/2026\n\nlblTime.Caption := FormatDateTime('hh:nn:ss', Now);\n// Output: 14:30:45\n\nlblFull.Caption := FormatDateTime('dddd, dd mmmm yyyy', Now);\n// Output: Sunday, 15 February 2026\n```\n\n## Format Codes\n| Code | Meaning | Example |\n|------|---------|----------|\n| dd | Day (2 digits) | 05 |\n| mm | Month (2 digits) | 02 |\n| yyyy | Year (4 digits) | 2026 |\n| hh | Hour (24h) | 14 |\n| nn | Minutes | 30 |\n| ss | Seconds | 45 |\n| dddd | Full day name | Sunday |\n| mmmm | Full month name | February |\n\n## Calculating Age\n```pascal\nvar\n  dBirth: TDateTime;\n  iAge: Integer;\nbegin\n  dBirth := EncodeDate(2008, 5, 15);\n  iAge := YearsBetween(Now, dBirth);\n  lblAge.Caption := 'Age: ' + IntToStr(iAge);\nend;\n```\n",
      },
    ],
    quiz: {
      title: "Strings, Dates, and Conversion Quiz",
      description: "Test your knowledge of advanced strings, date handling, and formatting.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What does StringReplace('Hello World', 'World', 'Delphi', [rfReplaceAll]) return?",
          type: "short_answer",
          correctAnswer: "Hello Delphi",
          explanation: "StringReplace replaces 'World' with 'Delphi'.",
        },
        {
          questionText: "Which function returns the current date and time?",
          type: "multiple_choice",
          options: ["Now", "Date", "Time", "Today"],
          correctAnswer: "Now",
          explanation: "Now returns both the current date and time.",
        },
        {
          questionText: "What does FormatDateTime('dd/mm/yyyy', Now) produce for 5 March 2026?",
          type: "short_answer",
          correctAnswer: "05/03/2026",
          explanation: "dd=05, mm=03, yyyy=2026.",
        },
        {
          questionText: "Write a function to check if a string is a palindrome.",
          type: "essay",
          correctAnswer:
            "Convert the string to uppercase. Loop from 1 to Length div 2, comparing s[i] with s[Length - i + 1]. If any pair differs, return False. If the loop completes without differences, return True.",
          explanation: "Compare characters from both ends moving inward.",
        },
        {
          questionText: "Which format code gives the full month name (e.g., 'February')?",
          type: "multiple_choice",
          options: ["mmmm", "mm", "mmm", "M"],
          correctAnswer: "mmmm",
          explanation: "mmmm displays the full month name in FormatDateTime.",
        },
      ],
    },
  },
  // ─── TERM 2 ───────────────────────────────────────────────
  {
    key: "it11-user-defined-methods",
    title: "User-Defined Methods",
    description:
      "Create your own procedures and functions in Delphi. Understand parameters (value vs reference), return types, and scope.",
    grade: 11,
    order: 5,
    capsTags: ["methods", "procedures", "functions", "parameters", "scope"],
    lessons: [
      {
        title: "Procedures and functions",
        type: "text",
        order: 1,
        content:
          "# User-Defined Methods\n\nA **method** is a named block of code that performs a specific task. In Delphi, there are two types:\n\n## Procedures\nPerform an action but **do not return** a value.\n```pascal\nprocedure DisplayGreeting(sName: String);\nbegin\n  ShowMessage('Hello, ' + sName + '!');\nend;\n\n// Call it:\nDisplayGreeting('Thabo');\n```\n\n## Functions\nPerform an action and **return a value**.\n```pascal\nfunction CalculateArea(rRadius: Real): Real;\nbegin\n  Result := Pi * rRadius * rRadius;\nend;\n\n// Call it:\nvar rArea: Real;\nrArea := CalculateArea(5.0);\nlblResult.Caption := FormatFloat('0.00', rArea);\n```\n\n## Why Use Methods?\n- **Reusability**: write once, call many times.\n- **Readability**: break complex programs into manageable pieces.\n- **Maintainability**: fix a bug in one place instead of many.\n- **Testing**: test each method independently.\n",
      },
      {
        title: "Parameters, scope, and variable passing",
        type: "text",
        order: 2,
        content:
          "# Parameters and Scope\n\n## Value Parameters (default)\nA **copy** of the argument is passed. Changes inside the method do not affect the original variable.\n```pascal\nprocedure DoubleValue(iNum: Integer); // value parameter\nbegin\n  iNum := iNum * 2; // only changes the local copy\nend;\n```\n\n## Reference Parameters (var)\nThe **original variable** is passed. Changes inside the method DO affect the original.\n```pascal\nprocedure DoubleValue(var iNum: Integer); // reference parameter\nbegin\n  iNum := iNum * 2; // changes the original variable\nend;\n\nvar x: Integer;\nx := 5;\nDoubleValue(x); // x is now 10\n```\n\n## Scope\n- **Local variables**: declared inside a method; only accessible within that method.\n- **Global variables**: declared at the form level; accessible everywhere in the unit.\n- Avoid excessive global variables — they make code harder to debug.\n\n## Example: Validate Input\n```pascal\nfunction IsValidMark(iMark: Integer): Boolean;\nbegin\n  Result := (iMark >= 0) AND (iMark <= 100);\nend;\n\n// Usage:\nif IsValidMark(StrToInt(edtMark.Text)) then\n  // process the mark\nelse\n  ShowMessage('Invalid mark! Enter 0-100.');\n```\n",
      },
    ],
    quiz: {
      title: "User-Defined Methods Quiz",
      description: "Test your understanding of procedures, functions, parameters, and scope.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the difference between a procedure and a function?",
          type: "short_answer",
          correctAnswer: "A procedure performs an action but does not return a value. A function performs an action and returns a value.",
          explanation: "Functions use Result to return a value; procedures do not.",
        },
        {
          questionText: "What keyword is used to pass a parameter by reference in Delphi?",
          type: "multiple_choice",
          options: ["var", "const", "ref", "out"],
          correctAnswer: "var",
          explanation: "The var keyword before a parameter makes it a reference parameter.",
        },
        {
          questionText: "If x = 10 and you call DoubleIt(x) where DoubleIt takes a value parameter, what is x after the call?",
          type: "short_answer",
          correctAnswer: "10",
          explanation: "Value parameters pass a copy, so the original is unchanged.",
        },
        {
          questionText: "What is scope in programming?",
          type: "multiple_choice",
          options: [
            "The region of code where a variable is accessible",
            "The size of an array",
            "The speed of a program",
            "The number of parameters in a function",
          ],
          correctAnswer: "The region of code where a variable is accessible",
          explanation: "Scope determines where a variable can be used.",
        },
        {
          questionText: "Write a function CalcAverage that takes a total (Integer) and count (Integer) and returns the average as a Real.",
          type: "essay",
          correctAnswer:
            "function CalcAverage(iTotal, iCount: Integer): Real;\nbegin\n  if iCount > 0 then\n    Result := iTotal / iCount\n  else\n    Result := 0;\nend;",
          explanation: "The function divides total by count, checking for division by zero.",
        },
      ],
    },
  },
  {
    key: "it11-database-fundamentals",
    title: "Database Fundamentals",
    description:
      "Understand relational database concepts: tables, fields, records, primary/foreign keys, data types, and the basics of SQL SELECT queries.",
    grade: 11,
    order: 6,
    capsTags: ["database", "tables", "keys", "sql", "select"],
    lessons: [
      {
        title: "Relational database concepts",
        type: "text",
        order: 1,
        content:
          "# Relational Database Concepts\n\nA **relational database** organizes data into **tables** (also called relations).\n\n## Key Terminology\n| Term | Description | Example |\n|------|-------------|----------|\n| Table | A collection of related data | tblStudents |\n| Field (column) | A single attribute | Surname, Mark |\n| Record (row) | A complete set of data for one entity | One student's data |\n| Primary Key (PK) | Uniquely identifies each record | StudentID |\n| Foreign Key (FK) | Links one table to another | ClassID in tblStudents |\n| Data Type | Type of data stored in a field | Integer, Text, Date |\n\n## Example: School Database\n**tblStudents**\n| StudentID (PK) | FirstName | Surname | ClassID (FK) | Mark |\n|----------------|-----------|---------|--------------|------|\n| 1 | Thabo | Molefe | 101 | 78 |\n| 2 | Lerato | Nkosi | 102 | 85 |\n| 3 | Johan | van Wyk | 101 | 62 |\n\n**tblClasses**\n| ClassID (PK) | ClassName | Teacher |\n|-------------|-----------|----------|\n| 101 | 11A | Ms Botha |\n| 102 | 11B | Mr Pillay |\n\n## Relationships\n- **One-to-Many**: one class has many students (most common).\n- **Many-to-Many**: requires a junction table.\n- **One-to-One**: rare, special cases.\n",
      },
      {
        title: "Introduction to SQL SELECT",
        type: "text",
        order: 2,
        content:
          "# SQL SELECT Queries\n\nSQL (Structured Query Language) is used to retrieve and manipulate data.\n\n## Basic SELECT\n```sql\nSELECT * FROM tblStudents;\n-- Returns all fields and all records\n\nSELECT FirstName, Surname FROM tblStudents;\n-- Returns only FirstName and Surname\n```\n\n## WHERE Clause (Filtering)\n```sql\nSELECT * FROM tblStudents WHERE Mark >= 70;\n\nSELECT * FROM tblStudents WHERE ClassID = 101 AND Mark > 50;\n\nSELECT * FROM tblStudents WHERE Surname LIKE 'N%';\n-- % is a wildcard: starts with 'N'\n```\n\n## ORDER BY (Sorting)\n```sql\nSELECT * FROM tblStudents ORDER BY Surname ASC;\n-- Ascending A-Z\n\nSELECT * FROM tblStudents ORDER BY Mark DESC;\n-- Descending, highest first\n```\n\n## Aggregate Functions\n| Function | Purpose |\n|----------|----------|\n| COUNT(*) | Count records |\n| SUM(field) | Add up values |\n| AVG(field) | Calculate average |\n| MAX(field) | Highest value |\n| MIN(field) | Lowest value |\n\n```sql\nSELECT COUNT(*) FROM tblStudents WHERE Mark >= 50;\n-- Count students who passed\n\nSELECT AVG(Mark) FROM tblStudents;\n-- Average mark\n```\n\n## DISTINCT\n```sql\nSELECT DISTINCT ClassID FROM tblStudents;\n-- Unique class IDs only\n```\n",
      },
      {
        title: "Using SQL in Delphi with ADO",
        type: "text",
        order: 3,
        content:
          "# SQL in Delphi (ADO)\n\nDelphi connects to databases using **ADO** (ActiveX Data Objects) components.\n\n## Key Components\n| Component | Purpose |\n|-----------|----------|\n| TADOConnection | Connects to the database file |\n| TADOQuery | Runs SQL queries |\n| TADOTable | Direct table access |\n| TDBGrid | Displays data in a table grid |\n| TDataSource | Links data components to visual components |\n\n## Running a SELECT Query\n```pascal\nprocedure TfrmMain.btnSearchClick(Sender: TObject);\nbegin\n  qryStudents.Close;\n  qryStudents.SQL.Clear;\n  qryStudents.SQL.Add('SELECT * FROM tblStudents');\n  qryStudents.SQL.Add('WHERE Mark >= 50');\n  qryStudents.SQL.Add('ORDER BY Surname ASC');\n  qryStudents.Open;\nend;\n```\n\n## Using Parameters (Safe Queries)\n```pascal\nqryStudents.Close;\nqryStudents.SQL.Clear;\nqryStudents.SQL.Add('SELECT * FROM tblStudents WHERE ClassID = :pClassID');\nqryStudents.Parameters.ParamByName('pClassID').Value := StrToInt(edtClass.Text);\nqryStudents.Open;\n```\n\n## Looping Through Results\n```pascal\nqryStudents.First;\nwhile not qryStudents.EOF do\nbegin\n  memOutput.Lines.Add(qryStudents['Surname'] + ': ' +\n    IntToStr(qryStudents['Mark']));\n  qryStudents.Next;\nend;\n```\n",
      },
    ],
    quiz: {
      title: "Database Fundamentals Quiz",
      description: "Test your understanding of relational databases and SQL SELECT.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is a primary key?",
          type: "short_answer",
          correctAnswer: "A field that uniquely identifies each record in a table.",
          explanation: "No two records can have the same primary key value.",
        },
        {
          questionText: "Write SQL to select all students with a mark above 70, sorted by surname.",
          type: "short_answer",
          correctAnswer: "SELECT * FROM tblStudents WHERE Mark > 70 ORDER BY Surname ASC",
          explanation: "Use WHERE for filtering and ORDER BY for sorting.",
        },
        {
          questionText: "What does the LIKE operator with '%' do in SQL?",
          type: "multiple_choice",
          options: [
            "Acts as a wildcard matching any sequence of characters",
            "Finds exact matches only",
            "Sorts results alphabetically",
            "Counts the number of records",
          ],
          correctAnswer: "Acts as a wildcard matching any sequence of characters",
          explanation: "'N%' matches any value starting with 'N'.",
        },
        {
          questionText: "What is the purpose of a foreign key?",
          type: "short_answer",
          correctAnswer: "To create a link between two tables by referencing the primary key of another table.",
          explanation: "Foreign keys establish relationships between tables.",
        },
        {
          questionText: "Explain the difference between COUNT(*) and SUM(field) in SQL.",
          type: "essay",
          correctAnswer:
            "COUNT(*) counts the number of records (rows) that match the criteria. SUM(field) adds up the numerical values in a specified field across all matching records.",
          explanation: "COUNT counts rows; SUM adds values.",
        },
      ],
    },
  },
  {
    key: "it11-text-files-advanced",
    title: "Advanced Text File Processing",
    description:
      "Process structured text files with delimiters, parse data into arrays, and combine file processing with database operations.",
    grade: 11,
    order: 7,
    capsTags: ["files", "textfiles", "parsing", "delimiters"],
    lessons: [
      {
        title: "Structured text files and delimiters",
        type: "text",
        order: 1,
        content:
          "# Structured Text Files\n\nText files often contain structured data with fields separated by a **delimiter** (e.g., comma, semicolon, hash).\n\n## Example File: students.txt\n```\nThabo;Molefe;78\nLerato;Nkosi;85\nJohan;van Wyk;62\n```\n\n## Parsing a Delimited Line\n```pascal\nvar\n  sLine, sFirst, sSurname, sMark: String;\n  iPos: Integer;\nbegin\n  sLine := 'Thabo;Molefe;78';\n\n  // Extract first name\n  iPos := Pos(';', sLine);\n  sFirst := Copy(sLine, 1, iPos - 1);\n  Delete(sLine, 1, iPos);\n\n  // Extract surname\n  iPos := Pos(';', sLine);\n  sSurname := Copy(sLine, 1, iPos - 1);\n  Delete(sLine, 1, iPos);\n\n  // Remaining is the mark\n  sMark := sLine;\nend;\n```\n\n## Reading File into Arrays\n```pascal\nvar\n  tFile: TextFile;\n  sLine: String;\n  iCount: Integer;\n  arrNames: array[1..100] of String;\n  arrMarks: array[1..100] of Integer;\nbegin\n  iCount := 0;\n  AssignFile(tFile, 'students.txt');\n  Reset(tFile);\n  while not EOF(tFile) do\n  begin\n    Inc(iCount);\n    Readln(tFile, sLine);\n    // Parse first field as name, last field as mark\n    arrNames[iCount] := Copy(sLine, 1, Pos(';', sLine) - 1);\n    arrMarks[iCount] := StrToInt(Copy(sLine, LastDelimiter(';', sLine) + 1, MaxInt));\n  end;\n  CloseFile(tFile);\nend;\n```\n",
      },
      {
        title: "Writing processed data back to files",
        type: "text",
        order: 2,
        content:
          "# Writing Processed Data\n\n## Processing and Saving Results\nA common exam pattern: read a file, process the data, and write results to a new file.\n\n```pascal\nvar\n  tInput, tOutput: TextFile;\n  sLine, sName: String;\n  iMark: Integer;\n  iPos: Integer;\nbegin\n  AssignFile(tInput, 'students.txt');\n  AssignFile(tOutput, 'results.txt');\n  Reset(tInput);\n  Rewrite(tOutput);\n\n  while not EOF(tInput) do\n  begin\n    Readln(tInput, sLine);\n    // Extract mark (last field)\n    iPos := LastDelimiter(';', sLine);\n    iMark := StrToInt(Copy(sLine, iPos + 1, MaxInt));\n    sName := Copy(sLine, 1, Pos(';', sLine) - 1);\n\n    if iMark >= 50 then\n      Writeln(tOutput, sName + ' - PASSED (' + IntToStr(iMark) + '%)')\n    else\n      Writeln(tOutput, sName + ' - FAILED (' + IntToStr(iMark) + '%)');\n  end;\n\n  CloseFile(tInput);\n  CloseFile(tOutput);\n  ShowMessage('Results written to results.txt');\nend;\n```\n\n## Tips for File Processing\n- Always check `FileExists` before `Reset`.\n- Use `try...finally` to ensure files are closed even if an error occurs.\n- Parse carefully — off-by-one errors are common with `Copy` and `Delete`.\n- Test with small files first.\n",
      },
    ],
    quiz: {
      title: "Advanced Text Files Quiz",
      description: "Test your file processing and data parsing skills.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is a delimiter in a text file?",
          type: "short_answer",
          correctAnswer: "A character used to separate fields in a line of data, such as a semicolon, comma, or hash.",
          explanation: "Delimiters structure data into parseable fields.",
        },
        {
          questionText: "Given the line 'Alice;Smith;92', write code to extract the surname 'Smith'.",
          type: "essay",
          correctAnswer:
            "Delete from start to first semicolon (removes 'Alice;'). Then use Copy from 1 to the position of the next semicolon minus 1 to get 'Smith'.",
          explanation: "Use Pos, Copy, and Delete to parse delimited text.",
        },
        {
          questionText: "What is the difference between Reset, Rewrite, and Append?",
          type: "multiple_choice",
          options: [
            "Reset reads, Rewrite creates/overwrites, Append adds to end",
            "Reset writes, Rewrite reads, Append deletes",
            "All three do the same thing",
            "Reset and Rewrite are the same, Append is different",
          ],
          correctAnswer: "Reset reads, Rewrite creates/overwrites, Append adds to end",
          explanation: "Each opens the file differently based on the intended operation.",
        },
        {
          questionText: "Why should you use try...finally when working with files?",
          type: "short_answer",
          correctAnswer: "To ensure the file is closed even if an error occurs during processing.",
          explanation: "The finally block always runs, preventing unclosed file handles.",
        },
        {
          questionText: "What happens if you call Rewrite on an existing file?",
          type: "multiple_choice",
          options: [
            "The existing content is erased and a new empty file is created",
            "Data is added to the end of the file",
            "An error occurs",
            "The file is opened for reading",
          ],
          correctAnswer: "The existing content is erased and a new empty file is created",
          explanation: "Rewrite always creates a fresh file, overwriting any existing content.",
        },
      ],
    },
  },
  // ─── TERM 3 ───────────────────────────────────────────────
  {
    key: "it11-database-design",
    title: "Database Design Concepts",
    description:
      "Learn Entity-Relationship Diagrams (ERDs), normalisation (1NF, 2NF, 3NF), data integrity, and referential integrity.",
    grade: 11,
    order: 8,
    capsTags: ["database", "erd", "normalisation", "integrity"],
    lessons: [
      {
        title: "Entity-Relationship Diagrams",
        type: "text",
        order: 1,
        content:
          "# Entity-Relationship Diagrams (ERDs)\n\nAn **ERD** is a visual representation of the tables and relationships in a database.\n\n## ERD Components\n- **Entity (rectangle)**: a table (e.g., Student, Class, Subject).\n- **Attribute (oval)**: a field in a table (e.g., Name, Mark).\n- **Relationship (diamond)**: how entities are connected.\n- **Primary Key**: underlined attribute.\n- **Foreign Key**: links to another table's PK.\n\n## Relationship Types\n| Type | Notation | Example |\n|------|----------|----------|\n| One-to-One (1:1) | 1 — 1 | Student has one profile |\n| One-to-Many (1:M) | 1 — * | Class has many students |\n| Many-to-Many (M:M) | * — * | Students take many subjects |\n\n## Resolving Many-to-Many\nM:M relationships need a **junction table**:\n```\ntblStudents (StudentID PK, ...)\ntblSubjects (SubjectID PK, ...)\ntblStudentSubjects (StudentID FK, SubjectID FK, Mark)\n```\nThe junction table's primary key is usually a composite of both foreign keys.\n\n## Steps to Create an ERD\n1. Identify entities (nouns in the requirements).\n2. Identify relationships (verbs: \"has\", \"takes\", \"belongs to\").\n3. Add attributes and keys.\n4. Resolve M:M with junction tables.\n",
      },
      {
        title: "Normalisation and data integrity",
        type: "text",
        order: 2,
        content:
          "# Normalisation\n\n**Normalisation** removes data redundancy (duplication) and ensures data integrity.\n\n## First Normal Form (1NF)\n- Each cell contains a single value (no lists or repeating groups).\n- Each row is unique (has a primary key).\n\n**Before 1NF:**\n| StudentID | Name | Subjects |\n|-----------|------|----------|\n| 1 | Thabo | IT, Maths |\n\n**After 1NF:**\n| StudentID | Name | Subject |\n|-----------|------|----------|\n| 1 | Thabo | IT |\n| 1 | Thabo | Maths |\n\n## Second Normal Form (2NF)\n- Must be in 1NF.\n- Every non-key field depends on the **whole** primary key (not just part of it).\n- Relevant when the PK is composite.\n\n## Third Normal Form (3NF)\n- Must be in 2NF.\n- No **transitive dependencies** — non-key fields depend only on the PK, not on other non-key fields.\n\n**Before 3NF:**\n| StudentID | Name | ClassID | ClassName |\n|-----------|------|---------|----------|\n\nClassName depends on ClassID, not StudentID → move to a separate table.\n\n## Data Integrity\n| Type | Description |\n|------|------------|\n| Entity integrity | Every table has a unique PK, no nulls in PK |\n| Referential integrity | FK values must match an existing PK or be null |\n| Domain integrity | Values must be of the correct type and range |\n",
      },
    ],
    quiz: {
      title: "Database Design Quiz",
      description: "Test your understanding of ERDs, normalisation, and data integrity.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is normalisation?",
          type: "short_answer",
          correctAnswer: "The process of organizing database tables to reduce data redundancy and improve data integrity.",
          explanation: "Normalisation eliminates repeating data and ensures dependencies are logical.",
        },
        {
          questionText: "How do you resolve a many-to-many relationship in a database?",
          type: "short_answer",
          correctAnswer: "Create a junction table with foreign keys referencing both related tables.",
          explanation: "The junction table breaks M:M into two 1:M relationships.",
        },
        {
          questionText: "What does 1NF require?",
          type: "multiple_choice",
          options: [
            "Each cell has a single value and each row is unique",
            "No transitive dependencies",
            "All fields depend on the whole primary key",
            "All tables have foreign keys",
          ],
          correctAnswer: "Each cell has a single value and each row is unique",
          explanation: "1NF eliminates repeating groups and ensures atomic values.",
        },
        {
          questionText: "What is referential integrity?",
          type: "multiple_choice",
          options: [
            "Foreign key values must match an existing primary key or be null",
            "Every table must have a primary key",
            "Data must be the correct type",
            "No table can have more than 10 fields",
          ],
          correctAnswer: "Foreign key values must match an existing primary key or be null",
          explanation: "Referential integrity prevents orphaned records.",
        },
        {
          questionText: "Explain with an example why 3NF removes transitive dependencies.",
          type: "essay",
          correctAnswer:
            "In a Students table with StudentID, Name, ClassID, and ClassName, ClassName depends on ClassID (not directly on StudentID). This is a transitive dependency. To achieve 3NF, move ClassID and ClassName to a separate Classes table. The Students table keeps only ClassID as a foreign key.",
          explanation: "3NF ensures non-key fields depend only on the primary key.",
        },
      ],
    },
  },
  {
    key: "it11-database-programming",
    title: "Database Programming in Delphi",
    description:
      "Execute SQL INSERT, UPDATE, DELETE, and GROUP BY queries from Delphi. Build data management applications with ADO.",
    grade: 11,
    order: 9,
    capsTags: ["database", "sql", "insert", "update", "delete", "groupby"],
    lessons: [
      {
        title: "SQL data manipulation (INSERT, UPDATE, DELETE)",
        type: "text",
        order: 1,
        content:
          "# SQL Data Manipulation\n\n## INSERT — Add a new record\n```sql\nINSERT INTO tblStudents (FirstName, Surname, ClassID, Mark)\nVALUES ('Sipho', 'Dlamini', 101, 73);\n```\n\n## UPDATE — Modify existing records\n```sql\nUPDATE tblStudents SET Mark = 80 WHERE StudentID = 1;\n\nUPDATE tblStudents SET ClassID = 102 WHERE Surname = 'Molefe';\n```\n\n## DELETE — Remove records\n```sql\nDELETE FROM tblStudents WHERE StudentID = 3;\n\nDELETE FROM tblStudents WHERE Mark < 30;\n```\n\n**Warning**: DELETE and UPDATE without WHERE affect ALL records!\n\n## GROUP BY and HAVING\n```sql\n-- Count students per class\nSELECT ClassID, COUNT(*) AS NumStudents\nFROM tblStudents\nGROUP BY ClassID;\n\n-- Average mark per class, only classes with average > 60\nSELECT ClassID, AVG(Mark) AS AvgMark\nFROM tblStudents\nGROUP BY ClassID\nHAVING AVG(Mark) > 60;\n```\n\n## GROUP BY vs WHERE vs HAVING\n- **WHERE**: filters individual rows before grouping.\n- **GROUP BY**: groups rows by a field.\n- **HAVING**: filters groups after grouping.\n",
      },
      {
        title: "Executing SQL from Delphi",
        type: "text",
        order: 2,
        content:
          "# SQL in Delphi Applications\n\n## ExecSQL vs Open\n- Use `Open` for SELECT queries (returns data).\n- Use `ExecSQL` for INSERT, UPDATE, DELETE (modifies data).\n\n## Adding a Record\n```pascal\nprocedure TfrmMain.btnAddClick(Sender: TObject);\nbegin\n  qryStudents.Close;\n  qryStudents.SQL.Clear;\n  qryStudents.SQL.Add('INSERT INTO tblStudents (FirstName, Surname, Mark)');\n  qryStudents.SQL.Add('VALUES (:pFirst, :pSurname, :pMark)');\n  qryStudents.Parameters.ParamByName('pFirst').Value := edtFirst.Text;\n  qryStudents.Parameters.ParamByName('pSurname').Value := edtSurname.Text;\n  qryStudents.Parameters.ParamByName('pMark').Value := StrToInt(edtMark.Text);\n  qryStudents.ExecSQL;\n  ShowMessage('Record added successfully!');\n  // Refresh the grid\n  RefreshGrid;\nend;\n```\n\n## Updating a Record\n```pascal\nqryStudents.SQL.Clear;\nqryStudents.SQL.Add('UPDATE tblStudents SET Mark = :pMark');\nqryStudents.SQL.Add('WHERE StudentID = :pID');\nqryStudents.Parameters.ParamByName('pMark').Value := StrToInt(edtMark.Text);\nqryStudents.Parameters.ParamByName('pID').Value := iSelectedID;\nqryStudents.ExecSQL;\n```\n\n## Deleting a Record\n```pascal\nif MessageDlg('Are you sure?', mtConfirmation, [mbYes, mbNo], 0) = mrYes then\nbegin\n  qryStudents.SQL.Clear;\n  qryStudents.SQL.Add('DELETE FROM tblStudents WHERE StudentID = :pID');\n  qryStudents.Parameters.ParamByName('pID').Value := iSelectedID;\n  qryStudents.ExecSQL;\nend;\n```\n\n## Always Use Parameters\nNever concatenate user input directly into SQL — it causes **SQL injection** vulnerabilities.\n",
      },
    ],
    quiz: {
      title: "Database Programming Quiz",
      description: "Test your SQL data manipulation and Delphi database programming skills.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Write SQL to insert a new student 'Naledi' with surname 'Khumalo' and mark 88.",
          type: "short_answer",
          correctAnswer: "INSERT INTO tblStudents (FirstName, Surname, Mark) VALUES ('Naledi', 'Khumalo', 88)",
          explanation: "INSERT INTO with VALUES adds a new record.",
        },
        {
          questionText: "What is the difference between Open and ExecSQL in Delphi?",
          type: "short_answer",
          correctAnswer: "Open is used for SELECT queries that return data. ExecSQL is used for INSERT, UPDATE, and DELETE queries that modify data.",
          explanation: "SELECT returns a dataset; modification queries don't.",
        },
        {
          questionText: "What does HAVING do in SQL?",
          type: "multiple_choice",
          options: [
            "Filters groups after GROUP BY",
            "Filters individual rows before grouping",
            "Sorts the results",
            "Joins two tables",
          ],
          correctAnswer: "Filters groups after GROUP BY",
          explanation: "HAVING applies conditions to aggregated groups, not individual rows.",
        },
        {
          questionText: "Why should you always use parameters instead of string concatenation in SQL queries?",
          type: "multiple_choice",
          options: [
            "To prevent SQL injection attacks",
            "To make queries run faster",
            "To use less memory",
            "To display better error messages",
          ],
          correctAnswer: "To prevent SQL injection attacks",
          explanation: "Parameters sanitize user input, preventing malicious SQL.",
        },
        {
          questionText: "Write SQL to find the average mark per ClassID, showing only classes with more than 5 students.",
          type: "essay",
          correctAnswer:
            "SELECT ClassID, AVG(Mark) AS AvgMark FROM tblStudents GROUP BY ClassID HAVING COUNT(*) > 5",
          explanation: "GROUP BY groups by class, HAVING filters groups by count.",
        },
      ],
    },
  },
  {
    key: "it11-social-implications",
    title: "Social Implications of Technology",
    description:
      "Explore cybercrime, intellectual property, the impact of technology on society, and South African legislation (POPIA, ECT Act).",
    grade: 11,
    order: 10,
    capsTags: ["social", "ethics", "cybercrime", "legislation", "popia"],
    lessons: [
      {
        title: "Cybercrime and digital citizenship",
        type: "text",
        order: 1,
        content:
          "# Cybercrime and Digital Citizenship\n\n## Types of Cybercrime\n| Crime | Description |\n|-------|------------|\n| Hacking | Unauthorized access to computer systems |\n| Identity theft | Stealing personal information to impersonate someone |\n| Phishing | Fake emails/websites to steal credentials |\n| Cyberbullying | Using technology to harass or intimidate |\n| Software piracy | Illegal copying/distribution of software |\n| Online fraud | Scams to steal money online |\n| Spreading malware | Creating/distributing viruses, ransomware |\n\n## Digital Citizenship\nBeing a responsible user of technology:\n- **Respect**: treat others online as you would in person.\n- **Educate**: learn about your digital rights and responsibilities.\n- **Protect**: safeguard your personal data and privacy.\n\n## Impact of Technology on Society\n### Positive\n- Access to information and education.\n- Global communication and collaboration.\n- Economic opportunities (remote work, e-commerce).\n- Medical advances (telemedicine, research).\n\n### Negative\n- Job displacement due to automation.\n- Privacy concerns and data breaches.\n- Technology addiction and screen time.\n- Environmental impact (e-waste, energy use).\n- Deepening inequality (digital divide).\n",
      },
      {
        title: "South African legislation",
        type: "text",
        order: 2,
        content:
          "# South African IT Legislation\n\n## POPIA (Protection of Personal Information Act, 2013)\n- **Purpose**: protect personal information processed by public and private bodies.\n- **Key principles**:\n  - Consent: must have permission to collect data.\n  - Purpose limitation: use data only for the stated purpose.\n  - Security: take reasonable steps to protect data.\n  - Data minimization: collect only what is needed.\n- **Information Regulator**: enforces POPIA.\n- **Penalties**: fines up to R10 million or imprisonment.\n\n## ECT Act (Electronic Communications and Transactions Act, 2002)\n- Governs electronic transactions and communications.\n- Makes cyber offences (hacking, data interception) criminal.\n- Gives legal recognition to electronic signatures and contracts.\n\n## Copyright Act\n- Protects original works: software, text, images, music.\n- No registration required — automatic upon creation.\n- Duration: generally life of author + 50 years.\n\n## Intellectual Property\n| Type | Protects | Example |\n|------|----------|----------|\n| Copyright | Creative works | Software code, books |\n| Patent | Inventions | New algorithm, device |\n| Trademark | Brand identity | Logos, brand names |\n| Trade secret | Confidential business info | Coca-Cola recipe |\n\n## Creative Commons\nAuthors can choose how their work is shared:\n- **CC BY**: share with credit.\n- **CC BY-SA**: share with credit + same license.\n- **CC BY-NC**: share with credit, non-commercial only.\n- **CC0**: public domain, no restrictions.\n",
      },
    ],
    quiz: {
      title: "Social Implications Quiz",
      description: "Test your knowledge of cybercrime, legislation, and digital citizenship.",
      difficulty: "easy",
      questions: [
        {
          questionText: "What is phishing?",
          type: "short_answer",
          correctAnswer: "Using fake emails or websites to trick people into revealing personal information such as passwords or banking details.",
          explanation: "Phishing is a common social engineering attack.",
        },
        {
          questionText: "What does POPIA protect?",
          type: "multiple_choice",
          options: [
            "Personal information of individuals",
            "Software patents",
            "Network infrastructure",
            "Government databases only",
          ],
          correctAnswer: "Personal information of individuals",
          explanation: "POPIA regulates how personal data is collected, used, and stored.",
        },
        {
          questionText: "Which South African law governs electronic transactions and cyber offences?",
          type: "multiple_choice",
          options: ["ECT Act", "POPIA", "Copyright Act", "Consumer Protection Act"],
          correctAnswer: "ECT Act",
          explanation: "The ECT Act covers electronic communications, transactions, and cyber offences.",
        },
        {
          questionText: "Name two positive and two negative impacts of technology on society.",
          type: "essay",
          correctAnswer:
            "Positive: 1. Access to information and online education. 2. Global communication enabling remote work and collaboration. Negative: 1. Job displacement due to automation and AI. 2. Privacy concerns and data breaches exposing personal information.",
          explanation: "Technology has both benefits and risks for society.",
        },
        {
          questionText: "What does CC BY-NC mean in Creative Commons licensing?",
          type: "short_answer",
          correctAnswer: "You may share and adapt the work with attribution (credit), but not for commercial purposes.",
          explanation: "BY = attribution required, NC = non-commercial use only.",
        },
      ],
    },
  },
  // ─── TERM 4 ───────────────────────────────────────────────
  {
    key: "it11-emerging-tech",
    title: "Emerging Technologies",
    description:
      "Explore the Internet of Things (IoT), big data, artificial intelligence, cloud computing evolution, and their impact on society.",
    grade: 11,
    order: 11,
    capsTags: ["iot", "big-data", "ai", "cloud", "emerging"],
    lessons: [
      {
        title: "Internet of Things and Big Data",
        type: "text",
        order: 1,
        content:
          "# Internet of Things (IoT)\n\nThe **IoT** connects everyday physical objects to the internet, allowing them to send and receive data.\n\n## Examples\n- **Smart home**: thermostats, lights, security cameras controlled via phone.\n- **Wearables**: fitness trackers, smartwatches monitoring health.\n- **Agriculture**: soil sensors for automated irrigation.\n- **Transport**: GPS tracking, self-driving cars.\n- **Industry**: machine sensors for predictive maintenance.\n\n## IoT Concerns\n- **Security**: more devices = more attack surfaces.\n- **Privacy**: devices constantly collecting data.\n- **Compatibility**: different brands use different standards.\n\n# Big Data\n\n**Big data** refers to extremely large datasets that traditional databases cannot handle efficiently.\n\n## The 5 V's of Big Data\n| V | Description |\n|---|------------|\n| Volume | Massive amounts of data (terabytes, petabytes) |\n| Velocity | Data generated at high speed (real-time) |\n| Variety | Different types (text, images, video, sensor data) |\n| Veracity | Accuracy and trustworthiness of data |\n| Value | Usefulness of data for decision-making |\n\n## Big Data Applications\n- Social media analytics.\n- Personalized recommendations (Netflix, YouTube).\n- Medical research and diagnostics.\n- Weather prediction.\n- Crime pattern analysis.\n",
      },
      {
        title: "AI, cloud trends, and internet services",
        type: "text",
        order: 2,
        content:
          "# Artificial Intelligence and Cloud Trends\n\n## Artificial Intelligence (AI)\nAI enables machines to simulate human intelligence.\n\n### Types of AI Applications\n- **Machine learning**: systems learn from data without explicit programming.\n- **Natural Language Processing (NLP)**: understanding human language (chatbots, translation).\n- **Computer vision**: identifying objects in images/video.\n- **Robotics**: automated physical tasks in manufacturing.\n\n### AI in Daily Life\n- Voice assistants (Siri, Google Assistant).\n- Spam email filtering.\n- Auto-complete and predictive text.\n- Facial recognition.\n\n## Cloud Computing Trends\n- **Edge computing**: processing data closer to where it's generated (not just in the cloud).\n- **Serverless computing**: run code without managing servers.\n- **Hybrid cloud**: combination of private and public cloud.\n\n## Modern Internet Services\n- **Streaming**: Netflix, Spotify, YouTube — media on demand.\n- **Social media**: platforms for communication and content sharing.\n- **Online learning**: Khan Academy, Coursera, Udemy.\n- **Digital banking**: online banking, mobile payments (SnapScan, Zapper).\n- **Government services**: e-filing (SARS), online applications.\n\n## Impact on Employment\n- New jobs: data scientists, AI engineers, cybersecurity specialists.\n- Displaced jobs: data entry, basic accounting, cashiers.\n- Emphasis on **digital literacy** as a core skill.\n",
      },
    ],
    quiz: {
      title: "Emerging Technologies Quiz",
      description: "Test your knowledge of IoT, big data, AI, and modern internet services.",
      difficulty: "easy",
      questions: [
        {
          questionText: "What does IoT stand for?",
          type: "short_answer",
          correctAnswer: "Internet of Things",
          explanation: "IoT connects physical devices to the internet.",
        },
        {
          questionText: "Name three of the 5 V's of Big Data.",
          type: "short_answer",
          correctAnswer: "Volume, Velocity, Variety (also Veracity and Value)",
          explanation: "The 5 V's describe the characteristics of big data.",
        },
        {
          questionText: "Which AI application understands and processes human language?",
          type: "multiple_choice",
          options: ["NLP (Natural Language Processing)", "Computer vision", "Robotics", "Edge computing"],
          correctAnswer: "NLP (Natural Language Processing)",
          explanation: "NLP enables machines to understand text and speech.",
        },
        {
          questionText: "Give two examples of IoT devices.",
          type: "short_answer",
          correctAnswer: "Smart thermostat and fitness tracker",
          explanation: "These are common IoT devices that connect to the internet.",
        },
        {
          questionText: "Explain how AI and automation might positively and negatively affect employment.",
          type: "essay",
          correctAnswer:
            "Positive: AI creates new job categories such as data scientists, AI engineers, and cybersecurity specialists. It also increases productivity and allows humans to focus on creative tasks. Negative: AI and automation can displace workers in routine jobs like data entry, cashiers, and basic accounting, requiring workers to retrain for new roles.",
          explanation: "AI transforms the job market with both opportunities and challenges.",
        },
      ],
    },
  },
  {
    key: "it11-consolidation-pat",
    title: "Consolidation and PAT Preparation",
    description:
      "Review all Grade 11 programming concepts through integrated exercises. Prepare for the Practical Assessment Task (PAT) combining databases, file handling, and UI development.",
    grade: 11,
    order: 12,
    capsTags: ["consolidation", "pat", "integration", "revision"],
    lessons: [
      {
        title: "Integrated programming review",
        type: "text",
        order: 1,
        content:
          "# Integrated Programming Review\n\n## Combining Skills\nThe PAT and final exam require combining multiple programming skills in a single project.\n\n### Typical Integrated Problem\nBuild a student management application that:\n1. Reads data from a text file into arrays.\n2. Displays data in a RichEdit or DBGrid.\n3. Allows searching, sorting, and filtering.\n4. Connects to a database with SQL queries.\n5. Uses user-defined methods for code organization.\n6. Validates all user input.\n\n## Checklist for Integration\n- [ ] File handling: read/write text files correctly.\n- [ ] Arrays: store, search, sort, calculate statistics.\n- [ ] Strings: parse, manipulate, format output.\n- [ ] Database: SELECT, INSERT, UPDATE, DELETE with parameters.\n- [ ] GUI: proper use of Edit, Memo, ComboBox, RadioGroup, DBGrid.\n- [ ] Methods: break code into logical procedures/functions.\n- [ ] Error handling: validate input (IsNumeric, range checks).\n- [ ] Date handling: format and calculate with dates.\n\n## Common Exam Patterns\n- Read a file → populate arrays → perform calculations.\n- Parse delimited strings → search array → display results.\n- SQL query → display in grid → modify with button clicks.\n",
      },
      {
        title: "PAT guidelines and project structure",
        type: "text",
        order: 2,
        content:
          "# PAT (Practical Assessment Task)\n\nThe PAT is worth **25%** of the final IT mark. It is completed in phases across Terms 2-4.\n\n## PAT Phases\n| Phase | Term | Focus | Weight |\n|-------|------|-------|--------|\n| Phase 1 | Term 2 | Analysis and design | ~30% |\n| Phase 2 | Term 3 | Coding and database | ~50% |\n| Phase 3 | Term 4 | Testing and documentation | ~20% |\n\n## Phase 1: Analysis and Design\n- Problem statement: what problem does the program solve?\n- IPO charts for each major function.\n- Database design: ERD, table structures.\n- User interface mockups/sketches.\n\n## Phase 2: Coding\n- Create the database and tables.\n- Build the Delphi application.\n- Implement all required features.\n- Use proper naming conventions (edtName, lblResult, btnSearch).\n- Comment your code.\n\n## Phase 3: Testing and Documentation\n- Test plan with expected vs actual results.\n- Screenshots of the running program.\n- User manual or help section.\n- Reflection: what worked, what you would improve.\n\n## PAT Tips\n- Start early — don't leave Phase 2 to the last week.\n- Follow your teacher's specific PAT brief.\n- Keep backups of your project (USB, cloud).\n- Use meaningful variable names and organize your code.\n",
      },
    ],
    quiz: {
      title: "Consolidation and PAT Quiz",
      description: "Review all Grade 11 concepts and PAT preparation.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What percentage of the final IT mark does the PAT contribute?",
          type: "multiple_choice",
          options: ["25%", "50%", "10%", "75%"],
          correctAnswer: "25%",
          explanation: "The PAT is worth 25% of the final IT mark.",
        },
        {
          questionText: "List three skills that should be combined in an integrated programming task.",
          type: "short_answer",
          correctAnswer: "File handling, database queries (SQL), and string manipulation.",
          explanation: "Integrated tasks combine multiple programming skills.",
        },
        {
          questionText: "In Phase 1 of the PAT, what design documents should you produce?",
          type: "essay",
          correctAnswer:
            "Phase 1 requires: a problem statement, IPO charts for each function, a database design (ERD and table structures), and user interface mockups or sketches.",
          explanation: "Phase 1 is about analysis and design before coding begins.",
        },
        {
          questionText: "Why is input validation important in a Delphi application?",
          type: "short_answer",
          correctAnswer: "To prevent runtime errors from invalid data (e.g., entering text where a number is expected) and to ensure data integrity.",
          explanation: "Validation prevents crashes and bad data.",
        },
        {
          questionText: "Which naming convention prefix is used for a Delphi edit box?",
          type: "multiple_choice",
          options: ["edt", "lbl", "btn", "mem"],
          correctAnswer: "edt",
          explanation: "Hungarian notation: edt = TEdit, lbl = TLabel, btn = TButton, mem = TMemo.",
        },
      ],
    },
  },
];
