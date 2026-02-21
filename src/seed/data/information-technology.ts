import type { ModuleSeed, SubjectSeed } from "../types.js";
import { grade10Modules } from "./information-technology-grade10.js";
import { grade11Modules } from "./information-technology-grade11.js";
import { chapterFocusModules } from "./information-technology-chapter-focus.js";
import { grade12ExamPrepModules } from "./information-technology-exam-prep.js";

export const subject: SubjectSeed = {
  name: "Information Technology",
  description:
    "CAPS-aligned Delphi programming and IT concepts covering Grades 10-12 with Paper 1 and Paper 2 content.",
  minGrade: 10,
  maxGrade: 12,
};

export const modules: ModuleSeed[] = [
  {
    key: "it12-algorithms-ipo",
    title: "Algorithms and IPO",
    description: "Plan solutions with step-by-step logic, IPO tables, and tracing.",
    grade: 12,
    order: 1,
    capsTags: ["algorithms", "ipo", "tracing"],
    lessons: [
      {
        title: "Algorithm basics",
        type: "text",
        order: 1,
        content:
          "# Algorithms\nAn algorithm is a step-by-step method used to solve a problem.\nOrder and precision matter because each step depends on the previous one.\n",
      },
      {
        title: "IPO tables and flow planning",
        type: "text",
        order: 2,
        content:
          "# IPO planning\nUse an IPO table to list inputs, processing, and outputs.\nFlowcharts and IPO tables help you plan before writing Delphi code.\n",
      },
      {
        title: "Tracing and logic-first marks",
        type: "text",
        order: 3,
        content:
          "# Tracing\nTracing loops and steps helps you check logic.\nExam guidance emphasizes correct logic even if syntax is not perfect.\n",
      },
    ],
    quiz: {
      title: "Algorithms and IPO Check",
      description: "Core concepts for planning and tracing solutions.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Define an algorithm.",
          type: "short_answer",
          correctAnswer: "A step-by-step method used to solve a problem.",
          explanation: "The study guide defines an algorithm as a step-by-step method.",
        },
        {
          questionText: "Why is order important in an algorithm?",
          type: "short_answer",
          correctAnswer:
            "Steps must be in the correct sequence to produce the correct result.",
          explanation: "Order and precision are highlighted in the guide.",
        },
        {
          questionText: "Which tool lists Inputs, Processing, and Outputs?",
          type: "multiple_choice",
          options: ["IPO table", "ERD", "Data dictionary", "SQL query"],
          correctAnswer: "IPO table",
          explanation: "IPO tables are used to plan inputs, processing, and outputs.",
        },
        {
          questionText:
            "Tracing a loop that adds 1, 2, 3, 4 gives which running totals?",
          type: "multiple_choice",
          options: ["1, 3, 6, 10", "1, 2, 3, 4", "2, 4, 6, 8", "4, 6, 8, 10"],
          correctAnswer: "1, 3, 6, 10",
          explanation: "The workbook memo shows these running totals.",
        },
        {
          questionText:
            "Describe how you would plan a solution before coding in Delphi.",
          type: "essay",
          correctAnswer:
            "Identify inputs and outputs, build an IPO table or flowchart, then write the algorithm steps.",
          explanation: "Planning with IPO tables and clear steps is emphasized.",
        },
      ],
    },
  },
  {
    key: "it12-selection-logic",
    title: "Selection and Boolean Logic",
    description: "Use IF, IF-ELSE, CASE, and AND/OR logic for decisions.",
    grade: 12,
    order: 2,
    capsTags: ["selection", "boolean", "gui"],
    lessons: [
      {
        title: "IF, IF-ELSE, and CASE",
        type: "text",
        order: 1,
        content:
          "# Selection\nSelection uses IF, IF-ELSE, or CASE to choose between outcomes.\nUse comparison operators to test conditions clearly.\n",
      },
      {
        title: "Boolean logic with AND and OR",
        type: "text",
        order: 2,
        content:
          "# Boolean logic\nCombine conditions with AND and OR for multi-rule decisions.\nA common pattern checks two inputs in any order.\n",
      },
      {
        title: "GUI-driven selection",
        type: "text",
        order: 3,
        content:
          "# GUI selection\nRadioGroup and ComboBox choices drive shapes, colors, and outputs.\nUse ItemIndex or Text to branch logic.\n",
      },
    ],
    quiz: {
      title: "Selection and Logic Check",
      description: "IF logic and GUI-driven decisions.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Which condition checks if a number is even?",
          type: "multiple_choice",
          options: ["n mod 2 = 0", "n / 2 = 0", "n + 2 = 0", "n mod 2 = 1"],
          correctAnswer: "n mod 2 = 0",
          explanation: "The workbook uses mod to test even and odd values.",
        },
        {
          questionText: "Write the condition for a pass if mark is at least 50.",
          type: "short_answer",
          correctAnswer: "mark >= 50",
          explanation: "The workbook uses mark >= 50 to display Pass.",
        },
        {
          questionText:
            "Which control is used to choose between circle and rectangle in the guide?",
          type: "multiple_choice",
          options: ["RadioGroup", "TEdit", "TMemo", "TTimer"],
          correctAnswer: "RadioGroup",
          explanation: "The selection pattern uses RadioGroup or ComboBox.",
        },
        {
          questionText:
            "Explain the logic to set a panel purple when colors are Red and Blue in any order.",
          type: "essay",
          correctAnswer:
            "Check (c1 = 'Red' and c2 = 'Blue') or (c1 = 'Blue' and c2 = 'Red') then set the panel color.",
          explanation: "The guide uses AND/OR to match either order.",
        },
        {
          questionText: "What is a CASE statement used for?",
          type: "short_answer",
          correctAnswer: "To select among multiple outcomes based on one value.",
          explanation: "CASE provides multi-branch selection.",
        },
      ],
    },
  },
  {
    key: "it12-loops-patterns",
    title: "Loops and Pattern Building",
    description: "Use for, while, and nested loops to build patterns and totals.",
    grade: 12,
    order: 3,
    capsTags: ["loops", "patterns", "accumulators"],
    lessons: [
      {
        title: "For and while loops",
        type: "text",
        order: 1,
        content:
          "# Loops\nFor loops handle counted repetition. While loops repeat while a condition is true.\nCounters and accumulators track totals inside loops.\n",
      },
      {
        title: "Nested loops for patterns",
        type: "text",
        order: 2,
        content:
          "# Nested loops\nNested loops build rows and columns, like number patterns in a RichEdit.\nThe outer loop controls rows; the inner loop builds each line.\n",
      },
      {
        title: "Accumulators and totals",
        type: "text",
        order: 3,
        content:
          "# Accumulators\nUse a running total to compute sums and averages.\nInitialize totals carefully and update inside the loop.\n",
      },
    ],
    quiz: {
      title: "Loops and Patterns Check",
      description: "Core loop patterns from the workbook.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Which loop repeats while a condition is true?",
          type: "multiple_choice",
          options: ["while", "for", "repeat until", "case"],
          correctAnswer: "while",
          explanation: "A while loop repeats while its condition is true.",
        },
        {
          questionText: "Write a loop to display numbers 5 down to 1.",
          type: "short_answer",
          correctAnswer: "for i := 5 downto 1 do ...",
          explanation: "The workbook asks for a descending loop.",
        },
        {
          questionText: "What does an accumulator store?",
          type: "multiple_choice",
          options: ["A running total", "A single input", "A loop limit", "A GUI label"],
          correctAnswer: "A running total",
          explanation: "Accumulators track totals as loops run.",
        },
        {
          questionText: "Why use nested loops in the pattern builder?",
          type: "short_answer",
          correctAnswer: "To build each row line by line using inner repetitions.",
          explanation: "The outer loop controls rows, inner loop builds content.",
        },
        {
          questionText:
            "Describe the output when the inner loop appends the row number i times.",
          type: "essay",
          correctAnswer:
            "Rows of repeated digits such as 1, 22, 333, and so on.",
          explanation: "This matches the pattern builder example in the guide.",
        },
      ],
    },
  },
  {
    key: "it12-strings-ascii",
    title: "Strings and ASCII Manipulation",
    description: "Work with string indexing, helper functions, and ASCII checks.",
    grade: 12,
    order: 4,
    capsTags: ["strings", "ascii", "algorithms"],
    lessons: [
      {
        title: "String indexing and helpers",
        type: "text",
        order: 1,
        content:
          "# Strings\nDelphi strings are 1-based: s[1] is the first character.\nCommon helpers include Length, Copy, Pos, Insert, Delete, and UpCase.\n",
      },
      {
        title: "Reverse words and remove vowels",
        type: "text",
        order: 2,
        content:
          "# String algorithms\nReverse a string and remove vowels to practice scanning and conditions.\nLoop from Length down to 1 and skip A, E, I, O, U.\n",
      },
      {
        title: "ASCII checks and sums",
        type: "text",
        order: 3,
        content:
          "# ASCII\nUse Ord and Chr to work with character codes.\nSum only uppercase letters by checking A..Z and using Ord values.\n",
      },
    ],
    quiz: {
      title: "Strings and ASCII Check",
      description: "String scanning and ASCII logic.",
      difficulty: "medium",
      questions: [
        {
          questionText: "In Delphi strings, what is the index of the first character?",
          type: "short_answer",
          correctAnswer: "1",
          explanation: "The guide notes that strings are 1-based.",
        },
        {
          questionText: "Which function converts a character to uppercase?",
          type: "multiple_choice",
          options: ["UpCase", "LowerCase", "Copy", "Pos"],
          correctAnswer: "UpCase",
          explanation: "UpCase is used in the string algorithm example.",
        },
        {
          questionText: "Outline steps to reverse a string and remove vowels.",
          type: "essay",
          correctAnswer:
            "Loop from end to start, convert each char to uppercase, skip vowels, and build the result.",
          explanation: "This matches the study guide algorithm.",
        },
        {
          questionText: "Which pair converts between characters and ASCII codes?",
          type: "multiple_choice",
          options: ["Ord and Chr", "Pos and Copy", "Inc and Dec", "StrToInt and IntToStr"],
          correctAnswer: "Ord and Chr",
          explanation: "Ord returns a code, Chr returns a character.",
        },
        {
          questionText: "Name two string functions used in the guide.",
          type: "short_answer",
          correctAnswer: "Length and Copy",
          explanation: "Length and Copy are listed in the string roadmap.",
        },
        {
          questionText: "What does ASCII refer to?",
          type: "short_answer",
          correctAnswer: "Numeric codes representing characters.",
          explanation: "The workbook defines ASCII as numeric character codes.",
        },
      ],
    },
  },
  {
    key: "it12-text-files",
    title: "Text Files and File Handling",
    description: "Read text files safely with FileExists, Reset, and EOF.",
    grade: 12,
    order: 5,
    capsTags: ["files", "eof", "averages"],
    lessons: [
      {
        title: "Text file basics",
        type: "text",
        order: 1,
        content:
          "# Text files\nUse AssignFile and Reset to open a file, then Readln inside a loop.\nEOF signals the end of the file.\n",
      },
      {
        title: "FileExists and averages",
        type: "text",
        order: 2,
        content:
          "# File checks\nCheck FileExists before reading.\nCalculate sum and count, then show the average with FormatFloat('0.00', value).\n",
      },
    ],
    quiz: {
      title: "File Handling Check",
      description: "Safe file reading and average calculation.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Which procedure opens a text file for reading?",
          type: "multiple_choice",
          options: ["Reset", "Rewrite", "CloseFile", "Append"],
          correctAnswer: "Reset",
          explanation: "Reset opens a text file for reading.",
        },
        {
          questionText: "What does EOF stand for?",
          type: "short_answer",
          correctAnswer: "End Of File",
          explanation: "EOF indicates the end of a text file.",
        },
        {
          questionText:
            "Describe the FileExists and average calculation pattern from the guide.",
          type: "essay",
          correctAnswer:
            "Check FileExists, open with AssignFile/Reset, loop with Readln until EOF, sum and count, then format the average.",
          explanation: "The workbook memo shows this exact pattern.",
        },
        {
          questionText: "Which function formats a number to two decimals?",
          type: "multiple_choice",
          options: ["FormatFloat('0.00', value)", "IntToStr", "Round", "FloatToStr"],
          correctAnswer: "FormatFloat('0.00', value)",
          explanation: "The guide formats averages with FormatFloat.",
        },
        {
          questionText: "Which statement reads a value from a text file?",
          type: "short_answer",
          correctAnswer: "Readln(tFile, value)",
          explanation: "Readln is used inside the EOF loop.",
        },
      ],
    },
  },
  {
    key: "it12-arrays-search-sort",
    title: "Arrays, Search, and Sorting",
    description: "Use 1D arrays, linear search, and bubble sort swaps.",
    grade: 12,
    order: 6,
    capsTags: ["arrays", "search", "sorting"],
    lessons: [
      {
        title: "1D arrays and averages",
        type: "text",
        order: 1,
        content:
          "# Arrays\nArrays store a list of values of the same type.\nUse loops to total values and compute averages.\n",
      },
      {
        title: "Linear search and flags",
        type: "text",
        order: 2,
        content:
          "# Search\nLinear search scans each item and uses a flag to track found or not found.\n",
      },
      {
        title: "Bubble sort and unique random numbers",
        type: "text",
        order: 3,
        content:
          "# Sorting\nBubble sort swaps neighboring values when out of order.\nUse nested loops and a flag to build unique random lists.\n",
      },
    ],
    quiz: {
      title: "Arrays and Sorting Check",
      description: "Search and sorting patterns from Paper 1.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is a 1D array used for?",
          type: "short_answer",
          correctAnswer: "To store a list of values of the same type.",
          explanation: "Arrays group related values in a single structure.",
        },
        {
          questionText: "Which search uses a flag variable to track found or not found?",
          type: "multiple_choice",
          options: ["Linear search", "Binary search", "Hash search", "Index search"],
          correctAnswer: "Linear search",
          explanation: "The guide mentions a flag-based linear search.",
        },
        {
          questionText: "Describe the swap step in bubble sort.",
          type: "essay",
          correctAnswer:
            "Temporarily store one value, swap neighboring elements when out of order, then continue passes.",
          explanation: "Bubble sort relies on repeated swaps.",
        },
        {
          questionText: "Why use nested loops for unique random numbers?",
          type: "short_answer",
          correctAnswer: "To check new numbers against all existing values for duplicates.",
          explanation: "A nested loop verifies uniqueness.",
        },
        {
          questionText: "Average the array [2, 4, 6, 8, 10].",
          type: "short_answer",
          correctAnswer: "6",
          explanation: "Sum is 30, divide by 5.",
        },
      ],
    },
  },
  {
    key: "it12-databases-sql",
    title: "Databases and SQL",
    description: "Work with tables, primary keys, and SQL queries in Delphi.",
    grade: 12,
    order: 7,
    capsTags: ["database", "sql", "ado"],
    lessons: [
      {
        title: "Tables, fields, and keys",
        type: "text",
        order: 1,
        content:
          "# Database basics\nTables contain rows and fields; a primary key uniquely identifies a record.\nRelationships link tables for structured data.\n",
      },
      {
        title: "SQL SELECT with filters",
        type: "text",
        order: 2,
        content:
          "# SQL\nUse SELECT with WHERE and ORDER BY.\nGROUP BY and COUNT summarize data for reports.\n",
      },
      {
        title: "ADOQuery and dataset loops",
        type: "text",
        order: 3,
        content:
          "# Delphi database work\nUse TADOQuery to run SQL.\nLoop through datasets using First, while not EOF, Edit/Post, Next.\n",
      },
    ],
    quiz: {
      title: "Database and SQL Check",
      description: "Core database terms and query patterns.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Which SQL keyword filters rows?",
          type: "multiple_choice",
          options: ["WHERE", "ORDER BY", "GROUP BY", "SELECT"],
          correctAnswer: "WHERE",
          explanation: "WHERE applies conditions to rows.",
        },
        {
          questionText: "What is a primary key?",
          type: "short_answer",
          correctAnswer: "A unique identifier for a record.",
          explanation: "Primary keys identify rows in a table.",
        },
        {
          questionText: "Which ADO component runs SQL queries in the guide?",
          type: "multiple_choice",
          options: ["TADOQuery", "TEdit", "TLabel", "TTimer"],
          correctAnswer: "TADOQuery",
          explanation: "The workbook uses TADOQuery for SQL.",
        },
        {
          questionText: "Describe the dataset loop pattern used in the guide.",
          type: "essay",
          correctAnswer:
            "Call First, loop while not EOF, Edit/Post changes, then Next to move forward.",
          explanation: "This is the standard dataset loop pattern.",
        },
        {
          questionText:
            "Write SQL to select learners with mark >= 60 ordered by surname.",
          type: "short_answer",
          correctAnswer:
            "SELECT * FROM Learners WHERE Mark >= 60 ORDER BY Surname",
          explanation: "Matches the SQL template in the workbook.",
        },
      ],
    },
  },
  {
    key: "it12-oop",
    title: "OOP Fundamentals",
    description: "Classes, constructors, and methods for structured programs.",
    grade: 12,
    order: 8,
    capsTags: ["oop", "classes", "methods"],
    lessons: [
      {
        title: "Classes and constructors",
        type: "text",
        order: 1,
        content:
          "# OOP basics\nA class defines attributes and behavior.\nConstructors initialize object state when creating instances.\n",
      },
      {
        title: "Methods and toString",
        type: "text",
        order: 2,
        content:
          "# Methods\nUse procedures to update data and functions to return values.\nA toString method builds a readable summary.\n",
      },
      {
        title: "Online status example",
        type: "text",
        order: 3,
        content:
          "# Example\nAn OnlineStatus function returns 'Online' or 'Offline' based on a boolean.\nUpdate counts with a procedure after actions.\n",
      },
    ],
    quiz: {
      title: "OOP Check",
      description: "Class structures and method patterns.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is a constructor used for?",
          type: "short_answer",
          correctAnswer: "To initialize an object's attributes.",
          explanation: "Constructors set up initial state.",
        },
        {
          questionText: "Where are attributes stored in the guide's OOP skeleton?",
          type: "multiple_choice",
          options: ["private section", "public section", "interface section", "uses section"],
          correctAnswer: "private section",
          explanation: "Attributes are placed under private.",
        },
        {
          questionText:
            "Explain an OnlineStatus function that returns 'Online' or 'Offline'.",
          type: "essay",
          correctAnswer:
            "If the boolean is true return 'Online', otherwise return 'Offline'.",
          explanation: "Matches the OOP example in the guide.",
        },
        {
          questionText: "What does a toString method help with?",
          type: "short_answer",
          correctAnswer: "Building a readable summary of an object.",
          explanation: "toString is used for display summaries.",
        },
        {
          questionText: "Which keyword defines a class in Delphi?",
          type: "multiple_choice",
          options: ["class", "object", "record", "unit"],
          correctAnswer: "class",
          explanation: "Delphi uses the class keyword.",
        },
      ],
    },
  },
  {
    key: "it12-theory-systems",
    title: "Systems, Communication, and Social Impact",
    description: "CAPS theory snapshot: systems, networks, data, and social issues.",
    grade: 12,
    order: 9,
    capsTags: ["systems", "communication", "social", "data"],
    lessons: [
      {
        title: "Systems technologies basics",
        type: "text",
        order: 1,
        content:
          "# Systems technologies\nA computer system includes input, processing, output, storage, and communication.\nHardware, software, and firmware (such as BIOS) work together.\n",
      },
      {
        title: "Communication and internet technologies",
        type: "text",
        order: 2,
        content:
          "# Communication\nNetworks enable data transmission using protocols like IP.\nEmail protocols like IMAP support message access.\nWeb 1.0 and new technologies like augmented reality are part of the theory snapshot.\n",
      },
      {
        title: "Data and social implications",
        type: "text",
        order: 3,
        content:
          "# Data and society\nData becomes information when processed and interpreted.\nTopics include ERD concepts, GUID/UUID, software licensing, and the digital divide.\n",
      },
    ],
    quiz: {
      title: "Systems and Theory Check",
      description: "Key Paper 2 concepts.",
      difficulty: "medium",
      questions: [
        {
          questionText: "BIOS is an example of which type of software?",
          type: "multiple_choice",
          options: ["Firmware", "Application software", "Shareware", "Middleware"],
          correctAnswer: "Firmware",
          explanation: "The theory snapshot lists BIOS under hardware/firmware.",
        },
        {
          questionText: "What does IP stand for?",
          type: "short_answer",
          correctAnswer: "Internet Protocol",
          explanation: "IP appears in the networking snapshot.",
        },
        {
          questionText: "IMAP is used for which task?",
          type: "multiple_choice",
          options: ["Email retrieval", "Web browsing", "File compression", "Printing"],
          correctAnswer: "Email retrieval",
          explanation: "IMAP is a mail protocol referenced in the theory list.",
        },
        {
          questionText: "Define the digital divide.",
          type: "short_answer",
          correctAnswer:
            "The gap between people with access to digital technology and those without it.",
          explanation: "Digital divide is listed under social implications.",
        },
        {
          questionText: "Explain the difference between data and information.",
          type: "essay",
          correctAnswer:
            "Data is raw facts; information is processed data that has meaning.",
          explanation: "Data and information management is a CAPS focus area.",
        },
        {
          questionText:
            "Which licensing concept allows sharing with conditions set by the author?",
          type: "multiple_choice",
          options: ["Creative Commons", "Proprietary", "Shareware", "Trialware"],
          correctAnswer: "Creative Commons",
          explanation: "Licensing is part of social implications.",
        },
      ],
    },
  },
  // ─── ADDITIONAL GRADE 12 MODULES (CAPS Gaps) ─────────────
  {
    key: "it12-2d-arrays",
    title: "Two-Dimensional Arrays",
    description:
      "Use 2D arrays to store tabular data. Access elements by row and column, and process grids of data.",
    grade: 12,
    order: 10,
    capsTags: ["arrays", "2d-arrays", "grids", "tables"],
    lessons: [
      {
        title: "Declaring and populating 2D arrays",
        type: "text",
        order: 1,
        content:
          "# Two-Dimensional Arrays\n\nA **2D array** stores data in rows and columns, like a table or spreadsheet.\n\n## Declaration\n```pascal\nvar\n  arrGrid: array[1..5, 1..4] of Integer;\n  // 5 rows, 4 columns\n```\n\n## Accessing Elements\n```pascal\narrGrid[2, 3] := 42;  // Row 2, Column 3\nlblResult.Caption := IntToStr(arrGrid[2, 3]);\n```\n\n## Populating with Nested Loops\n```pascal\nfor iRow := 1 to 5 do\n  for iCol := 1 to 4 do\n    arrGrid[iRow, iCol] := iRow * iCol;\n```\n\n## Displaying in a RichEdit\n```pascal\nfor iRow := 1 to 5 do\nbegin\n  sLine := '';\n  for iCol := 1 to 4 do\n    sLine := sLine + Format('%5d', [arrGrid[iRow, iCol]]);\n  redOutput.Lines.Add(sLine);\nend;\n```\n\n## Real-World Use Cases\n- Student marks (rows = students, columns = subjects).\n- Game boards (chess, tic-tac-toe).\n- Timetables (rows = periods, columns = days).\n",
      },
      {
        title: "Processing 2D arrays",
        type: "text",
        order: 2,
        content:
          "# Processing 2D Arrays\n\n## Row Totals and Column Totals\n```pascal\n// Row totals\nfor iRow := 1 to iRows do\nbegin\n  iRowTotal := 0;\n  for iCol := 1 to iCols do\n    iRowTotal := iRowTotal + arrGrid[iRow, iCol];\n  redOutput.Lines.Add('Row ' + IntToStr(iRow) + ' total: ' + IntToStr(iRowTotal));\nend;\n\n// Column totals\nfor iCol := 1 to iCols do\nbegin\n  iColTotal := 0;\n  for iRow := 1 to iRows do\n    iColTotal := iColTotal + arrGrid[iRow, iCol];\n  redOutput.Lines.Add('Col ' + IntToStr(iCol) + ' total: ' + IntToStr(iColTotal));\nend;\n```\n\n## Finding Maximum in a 2D Array\n```pascal\niMax := arrGrid[1, 1];\niMaxRow := 1;\niMaxCol := 1;\nfor iRow := 1 to iRows do\n  for iCol := 1 to iCols do\n    if arrGrid[iRow, iCol] > iMax then\n    begin\n      iMax := arrGrid[iRow, iCol];\n      iMaxRow := iRow;\n      iMaxCol := iCol;\n    end;\n```\n\n## Loading from a Text File\n```pascal\nAssignFile(tFile, 'grid.txt');\nReset(tFile);\niRow := 0;\nwhile not EOF(tFile) do\nbegin\n  Inc(iRow);\n  Readln(tFile, sLine);\n  // Parse columns from sLine using delimiters\nend;\nCloseFile(tFile);\n```\n",
      },
    ],
    quiz: {
      title: "2D Arrays Quiz",
      description: "Test your understanding of two-dimensional arrays.",
      difficulty: "medium",
      questions: [
        {
          questionText: "How do you access the element in row 3, column 2 of arrGrid?",
          type: "short_answer",
          correctAnswer: "arrGrid[3, 2]",
          explanation: "2D arrays are accessed with [row, column] notation.",
        },
        {
          questionText: "What is the purpose of nested loops with 2D arrays?",
          type: "multiple_choice",
          options: [
            "To traverse every element by iterating through rows and columns",
            "To sort the array",
            "To delete elements",
            "To resize the array",
          ],
          correctAnswer: "To traverse every element by iterating through rows and columns",
          explanation: "The outer loop handles rows, the inner loop handles columns.",
        },
        {
          questionText: "Write code to calculate the total of all values in a 2D array arrGrid[1..3, 1..4].",
          type: "essay",
          correctAnswer:
            "iTotal := 0;\nfor iRow := 1 to 3 do\n  for iCol := 1 to 4 do\n    iTotal := iTotal + arrGrid[iRow, iCol];",
          explanation: "Use nested loops to visit every element and add it to a running total.",
        },
        {
          questionText: "Give one real-world example of data suited for a 2D array.",
          type: "short_answer",
          correctAnswer: "A marks sheet with rows for students and columns for subjects.",
          explanation: "2D arrays model any tabular data naturally.",
        },
        {
          questionText: "How many elements does array[1..4, 1..6] of Integer contain?",
          type: "short_answer",
          correctAnswer: "24",
          explanation: "4 rows × 6 columns = 24 elements.",
        },
      ],
    },
  },
  {
    key: "it12-advanced-sql",
    title: "Advanced SQL and Database Manipulation",
    description:
      "Master SQL JOINs, subqueries, INSERT, UPDATE, DELETE, data warehousing concepts, and data mining basics.",
    grade: 12,
    order: 11,
    capsTags: ["sql", "joins", "subqueries", "dml", "data-warehousing"],
    lessons: [
      {
        title: "SQL JOINs",
        type: "text",
        order: 1,
        content:
          "# SQL JOINs\n\nJOINs combine data from two or more related tables.\n\n## INNER JOIN\nReturns only rows that have matching values in both tables.\n```sql\nSELECT s.FirstName, s.Surname, c.ClassName\nFROM tblStudents s\nINNER JOIN tblClasses c ON s.ClassID = c.ClassID;\n```\n\n## LEFT JOIN\nReturns all rows from the left table and matched rows from the right. Unmatched rows show NULL.\n```sql\nSELECT s.FirstName, c.ClassName\nFROM tblStudents s\nLEFT JOIN tblClasses c ON s.ClassID = c.ClassID;\n```\n\n## Multiple JOINs\n```sql\nSELECT s.Surname, sub.SubjectName, e.Mark\nFROM tblStudents s\nINNER JOIN tblEnrolments e ON s.StudentID = e.StudentID\nINNER JOIN tblSubjects sub ON e.SubjectID = sub.SubjectID\nWHERE e.Mark >= 50\nORDER BY s.Surname;\n```\n\n## Subqueries\nA query within a query:\n```sql\n-- Students with marks above average\nSELECT * FROM tblStudents\nWHERE Mark > (SELECT AVG(Mark) FROM tblStudents);\n\n-- Students in the class with the most members\nSELECT * FROM tblStudents\nWHERE ClassID = (\n  SELECT ClassID FROM tblStudents\n  GROUP BY ClassID\n  ORDER BY COUNT(*) DESC\n  LIMIT 1\n);\n```\n",
      },
      {
        title: "Data concepts: warehousing, mining, and collection",
        type: "text",
        order: 2,
        content:
          "# Data Concepts\n\n## Data Collection Methods\n- **Surveys/questionnaires**: structured response collection.\n- **Observation**: recording events as they happen.\n- **Interviews**: direct questioning.\n- **Electronic data capture**: sensors, web forms, transaction logs.\n- **Web scraping**: extracting data from websites.\n\n## Data Warehousing\nA **data warehouse** is a large, centralized repository that stores data from multiple sources for analysis.\n- Stores historical and current data.\n- Optimized for reading and analysis, not transaction processing.\n- Uses ETL (Extract, Transform, Load) to integrate data.\n\n## Data Mining\n**Data mining** is the process of discovering patterns, trends, and insights from large datasets.\n\n### Techniques\n| Technique | Description |\n|-----------|------------|\n| Classification | Categorizing data into predefined groups |\n| Clustering | Grouping similar data points together |\n| Association | Finding relationships between variables (e.g., customers who buy X also buy Y) |\n| Prediction | Forecasting future trends from historical data |\n\n### Applications\n- Retail: product recommendations.\n- Banking: fraud detection.\n- Healthcare: disease pattern identification.\n- Marketing: customer segmentation.\n\n## Database Normalisation Review (Grade 12)\n- **1NF**: atomic values, unique rows.\n- **2NF**: no partial dependencies (non-key depends on full PK).\n- **3NF**: no transitive dependencies.\n- **Denormalisation**: sometimes used in data warehouses for faster reads.\n",
      },
    ],
    quiz: {
      title: "Advanced SQL and Data Concepts Quiz",
      description: "Test your knowledge of JOINs, subqueries, and data warehousing/mining.",
      difficulty: "hard",
      questions: [
        {
          questionText: "What is the difference between INNER JOIN and LEFT JOIN?",
          type: "essay",
          correctAnswer:
            "INNER JOIN returns only rows with matching values in both tables. LEFT JOIN returns all rows from the left table, and matched rows from the right table. Where there is no match, the right table columns show NULL.",
          explanation: "INNER = intersection, LEFT = all from left + matches from right.",
        },
        {
          questionText: "Write a subquery to find students with marks above the class average.",
          type: "short_answer",
          correctAnswer: "SELECT * FROM tblStudents WHERE Mark > (SELECT AVG(Mark) FROM tblStudents)",
          explanation: "The subquery calculates the average; the outer query filters above it.",
        },
        {
          questionText: "What does ETL stand for in data warehousing?",
          type: "multiple_choice",
          options: ["Extract, Transform, Load", "Enter, Transfer, Log", "Encrypt, Transmit, Link", "Edit, Test, Launch"],
          correctAnswer: "Extract, Transform, Load",
          explanation: "ETL is the process of moving data into a data warehouse.",
        },
        {
          questionText: "Which data mining technique groups similar data points together?",
          type: "multiple_choice",
          options: ["Clustering", "Classification", "Association", "Prediction"],
          correctAnswer: "Clustering",
          explanation: "Clustering finds natural groupings without predefined categories.",
        },
        {
          questionText: "What is the purpose of a data warehouse?",
          type: "short_answer",
          correctAnswer: "To store large amounts of historical and current data from multiple sources in a centralized repository optimized for analysis and reporting.",
          explanation: "Data warehouses support business intelligence and decision-making.",
        },
      ],
    },
  },
  {
    key: "it12-advanced-oop",
    title: "Advanced OOP: Inheritance and Polymorphism",
    description:
      "Extend classes with inheritance, override methods with polymorphism, and use abstract classes in Delphi.",
    grade: 12,
    order: 12,
    capsTags: ["oop", "inheritance", "polymorphism", "abstract"],
    lessons: [
      {
        title: "Inheritance",
        type: "text",
        order: 1,
        content:
          "# Inheritance\n\n**Inheritance** allows a new class to extend an existing class, inheriting its attributes and methods.\n\n## Terminology\n- **Base class / Parent class / Superclass**: the class being inherited from.\n- **Derived class / Child class / Subclass**: the new class that inherits.\n\n## Delphi Syntax\n```pascal\ntype\n  // Base class\n  TAnimal = class\n  private\n    fName: String;\n    fAge: Integer;\n  public\n    constructor Create(sName: String; iAge: Integer);\n    function ToString: String; virtual;\n    function GetName: String;\n  end;\n\n  // Derived class\n  TDog = class(TAnimal)\n  private\n    fBreed: String;\n  public\n    constructor Create(sName: String; iAge: Integer; sBreed: String);\n    function ToString: String; override;\n    function GetBreed: String;\n  end;\n```\n\n## Benefits of Inheritance\n- **Code reuse**: shared code stays in the base class.\n- **Extensibility**: add new features without modifying existing code.\n- **Hierarchy**: models real-world IS-A relationships (a Dog IS-A Animal).\n\n## Constructor Chaining\n```pascal\nconstructor TDog.Create(sName: String; iAge: Integer; sBreed: String);\nbegin\n  inherited Create(sName, iAge);  // call parent constructor\n  fBreed := sBreed;\nend;\n```\n",
      },
      {
        title: "Polymorphism and abstract classes",
        type: "text",
        order: 2,
        content:
          "# Polymorphism\n\n**Polymorphism** (\"many forms\") allows a method to behave differently depending on the object that calls it.\n\n## How It Works in Delphi\n1. Declare the method as `virtual` in the base class.\n2. `override` it in the derived class.\n\n```pascal\n// Base class\nfunction TAnimal.ToString: String;\nbegin\n  Result := fName + ' (Age: ' + IntToStr(fAge) + ')';\nend;\n\n// Derived class overrides\nfunction TDog.ToString: String;\nbegin\n  Result := inherited ToString + ' Breed: ' + fBreed;\nend;\n```\n\n## Using Polymorphism\n```pascal\nvar\n  objAnimal: TAnimal;\nbegin\n  objAnimal := TDog.Create('Rex', 5, 'Labrador');\n  ShowMessage(objAnimal.ToString);\n  // Calls TDog.ToString because of polymorphism\n  // Output: Rex (Age: 5) Breed: Labrador\nend;\n```\n\n## Abstract Classes and Methods\nAn **abstract** method has no implementation in the base class — derived classes MUST override it.\n```pascal\ntype\n  TShape = class\n  public\n    function CalcArea: Real; virtual; abstract;\n    function ToString: String; virtual; abstract;\n  end;\n\n  TCircle = class(TShape)\n  private\n    fRadius: Real;\n  public\n    constructor Create(rRadius: Real);\n    function CalcArea: Real; override;\n    function ToString: String; override;\n  end;\n```\n\nYou cannot create an instance of an abstract class directly — you must use a concrete derived class.\n",
      },
    ],
    quiz: {
      title: "Advanced OOP Quiz",
      description: "Test your understanding of inheritance, polymorphism, and abstract classes.",
      difficulty: "hard",
      questions: [
        {
          questionText: "What is inheritance in OOP?",
          type: "short_answer",
          correctAnswer: "The ability of a new class (child) to inherit attributes and methods from an existing class (parent), enabling code reuse and hierarchy.",
          explanation: "Inheritance models IS-A relationships.",
        },
        {
          questionText: "What keywords are used to implement polymorphism in Delphi?",
          type: "multiple_choice",
          options: ["virtual and override", "static and dynamic", "public and private", "var and const"],
          correctAnswer: "virtual and override",
          explanation: "virtual in the base class, override in the derived class.",
        },
        {
          questionText: "What is 'inherited' used for in a constructor?",
          type: "short_answer",
          correctAnswer: "To call the parent class constructor to initialize inherited attributes before setting the child class's own attributes.",
          explanation: "inherited ensures the base class is properly initialized.",
        },
        {
          questionText: "Can you create an instance of an abstract class? Explain why or why not.",
          type: "essay",
          correctAnswer:
            "No, you cannot create an instance of an abstract class because it contains abstract methods that have no implementation. You must create an instance of a concrete derived class that provides implementations for all abstract methods.",
          explanation: "Abstract classes serve as blueprints; only concrete subclasses can be instantiated.",
        },
        {
          questionText: "What does polymorphism mean?",
          type: "multiple_choice",
          options: [
            "A method can behave differently depending on the object that calls it",
            "A class can only have one method",
            "Variables can change type at runtime",
            "All methods must be public",
          ],
          correctAnswer: "A method can behave differently depending on the object that calls it",
          explanation: "Polymorphism (many forms) allows overridden methods to behave differently per class.",
        },
      ],
    },
  },
  {
    key: "it12-computer-management-advanced",
    title: "Computer Management and Emerging Technologies",
    description:
      "Advanced computer management, cloud computing, AI, VR/AR, and their impact on business and society.",
    grade: 12,
    order: 13,
    capsTags: ["management", "cloud", "ai", "vr", "ar", "emerging"],
    lessons: [
      {
        title: "Advanced computer management",
        type: "text",
        order: 1,
        content:
          "# Advanced Computer Management\n\n## Troubleshooting Methodology\n1. Identify the problem (what changed? when did it start?).\n2. Establish a theory of probable cause.\n3. Test the theory.\n4. Establish a plan of action.\n5. Implement the solution.\n6. Verify and document.\n\n## Performance Monitoring\n- **Task Manager** (Windows): view CPU, memory, disk, network usage.\n- High CPU = too many processes or malware.\n- High memory = need more RAM or close applications.\n- High disk = background processes, fragmentation (HDD), or failing drive.\n\n## Backup Strategies\n| Type | Description | Speed |\n|------|-------------|-------|\n| Full backup | Copies all data | Slowest, most complete |\n| Incremental | Copies only changes since last backup | Fast backup, slow restore |\n| Differential | Copies changes since last full backup | Medium |\n\n## Disaster Recovery\n- Keep offsite backups.\n- Document recovery procedures.\n- Test recovery regularly.\n- Use RAID for server storage redundancy.\n",
      },
      {
        title: "Cloud, AI, VR, and AR",
        type: "text",
        order: 2,
        content:
          "# Emerging Technologies\n\n## Cloud Computing (Advanced)\n- **Public cloud**: shared infrastructure (AWS, Azure, Google Cloud).\n- **Private cloud**: dedicated to one organization.\n- **Hybrid cloud**: combines public and private.\n- **Multi-cloud**: using services from multiple providers.\n\n## Artificial Intelligence in Detail\n- **Narrow AI**: designed for specific tasks (chess, translation).\n- **General AI**: theoretical, human-level intelligence (not yet achieved).\n- **Machine learning**: algorithms improve through experience.\n- **Deep learning**: neural networks with many layers, used for image/speech recognition.\n\n## Virtual Reality (VR)\n- Fully immersive digital environment.\n- Uses headsets (Oculus, HTC Vive).\n- Applications: gaming, training simulations, virtual tours, therapy.\n\n## Augmented Reality (AR)\n- Overlays digital content on the real world.\n- Uses phones or AR glasses.\n- Applications: Pokémon GO, furniture placement (IKEA app), heads-up displays.\n\n## Mixed Reality (MR)\n- Blends VR and AR — digital objects interact with the real world.\n- Example: Microsoft HoloLens.\n\n## Impact on Business\n- Remote work enabled by cloud.\n- AI automates repetitive tasks.\n- VR/AR transform retail, real estate, education.\n- New ethical questions around AI bias and job displacement.\n",
      },
    ],
    quiz: {
      title: "Computer Management and Emerging Tech Quiz",
      description: "Test your knowledge of management techniques and emerging technologies.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the difference between VR and AR?",
          type: "essay",
          correctAnswer:
            "VR (Virtual Reality) is a fully immersive digital environment that replaces the real world. AR (Augmented Reality) overlays digital content on top of the real world. VR uses headsets for full immersion; AR typically uses phones or glasses to enhance reality.",
          explanation: "VR replaces reality; AR enhances it.",
        },
        {
          questionText: "What type of backup copies only changes since the last full backup?",
          type: "multiple_choice",
          options: ["Differential", "Full", "Incremental", "Mirror"],
          correctAnswer: "Differential",
          explanation: "Differential copies everything changed since the last full backup.",
        },
        {
          questionText: "What is hybrid cloud?",
          type: "short_answer",
          correctAnswer: "A combination of public and private cloud infrastructure, allowing data and applications to be shared between them.",
          explanation: "Hybrid cloud gives flexibility to keep sensitive data private while using public cloud for other workloads.",
        },
        {
          questionText: "What is the difference between narrow AI and general AI?",
          type: "short_answer",
          correctAnswer: "Narrow AI is designed for specific tasks (e.g., chess, translation). General AI would have human-level intelligence across all tasks, but has not been achieved yet.",
          explanation: "All current AI systems are narrow AI.",
        },
        {
          questionText: "List the six steps of a troubleshooting methodology.",
          type: "short_answer",
          correctAnswer: "1. Identify the problem 2. Establish a theory 3. Test the theory 4. Establish a plan 5. Implement the solution 6. Verify and document",
          explanation: "A systematic approach to solving technical problems.",
        },
      ],
    },
  },
  {
    key: "it12-internet-networks-security",
    title: "Internet Services, Networks, and Security",
    description:
      "SEO, online applications, network protocols, SSL/TLS, digital certificates, and the impact of social networking.",
    grade: 12,
    order: 14,
    capsTags: ["internet", "seo", "networks", "security", "ssl", "social-networking"],
    lessons: [
      {
        title: "Internet services and SEO",
        type: "text",
        order: 1,
        content:
          "# Internet Services (Grade 12)\n\n## Search Engine Optimization (SEO)\n**SEO** improves a website's ranking in search engine results.\n\n### Key SEO Techniques\n- **Keywords**: use relevant keywords in titles, headings, and content.\n- **Meta tags**: describe page content for search engines.\n- **Quality content**: original, regularly updated content ranks higher.\n- **Mobile-friendly**: responsive design is a ranking factor.\n- **Page speed**: faster pages rank better.\n- **Backlinks**: links from other reputable sites increase authority.\n- **HTTPS**: secure sites are preferred by search engines.\n\n## Online Applications\n- **Web apps**: run in browsers (Google Docs, Canva, Figma).\n- **Progressive Web Apps (PWAs)**: web apps that behave like native apps.\n- **API-based services**: apps communicate via APIs (REST, JSON).\n\n## E-Government Services\n- SARS eFiling: tax submissions.\n- eNaTIS: vehicle licensing.\n- DHA: ID and passport applications.\n- Benefits: 24/7 access, reduced queues, environmental savings.\n\n## Online Collaboration (Advanced)\n- Real-time document editing (Google Docs).\n- Version control and change tracking.\n- Video conferencing with screen sharing.\n- Project management tools (Trello, Asana).\n",
      },
      {
        title: "Network security and social implications",
        type: "text",
        order: 2,
        content:
          "# Network Security (Grade 12 Level)\n\n## SSL/TLS and Digital Certificates\n- **SSL/TLS**: protocols that encrypt data between browser and server.\n- **Digital certificate**: issued by a Certificate Authority (CA) to verify a website's identity.\n- **HTTPS**: HTTP + SSL/TLS encryption.\n- The browser padlock icon indicates a valid certificate.\n\n## Advanced Security Concepts\n- **Two-factor authentication (2FA)**: password + second factor (OTP, biometric).\n- **Biometric security**: fingerprints, facial recognition, iris scanning.\n- **Network segmentation**: isolating parts of a network for security.\n- **Penetration testing**: authorized testing of security vulnerabilities.\n\n## Social Networking Implications\n- **Privacy**: personal data shared on social media can be misused.\n- **Digital footprint**: everything posted online leaves a permanent trail.\n- **Fake news**: misinformation spreads rapidly on social platforms.\n- **Recruitment**: employers check social media profiles.\n- **Online reputation**: negative posts can damage careers and relationships.\n\n## Cybercrime (Grade 12 Focus)\n- **Ransomware**: encrypts files, demands payment.\n- **Advanced phishing**: spear phishing targets specific individuals.\n- **Cryptojacking**: using someone's computer to mine cryptocurrency.\n- **South African legislation**: Cybercrimes Act (2020) criminalizes cybercrime and provides for reporting obligations.\n",
      },
    ],
    quiz: {
      title: "Internet, Networks, and Security Quiz",
      description: "Test your Grade 12 knowledge of internet services, SEO, and security.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Name three SEO techniques to improve website ranking.",
          type: "short_answer",
          correctAnswer: "Using relevant keywords, creating quality content, and ensuring the site is mobile-friendly.",
          explanation: "SEO uses multiple techniques to improve search engine ranking.",
        },
        {
          questionText: "What is a digital certificate?",
          type: "short_answer",
          correctAnswer: "A document issued by a Certificate Authority that verifies a website's identity and enables encrypted connections via SSL/TLS.",
          explanation: "Digital certificates enable HTTPS and the browser padlock icon.",
        },
        {
          questionText: "What is spear phishing?",
          type: "multiple_choice",
          options: [
            "A targeted phishing attack aimed at a specific individual",
            "A general spam email campaign",
            "A type of network scanning",
            "A virus that spreads through USB drives",
          ],
          correctAnswer: "A targeted phishing attack aimed at a specific individual",
          explanation: "Spear phishing is personalized, making it more convincing than generic phishing.",
        },
        {
          questionText: "Why is your digital footprint important?",
          type: "essay",
          correctAnswer:
            "Your digital footprint is the trail of data you leave online through posts, comments, likes, and browsing history. It is permanent and can be viewed by employers, universities, and others. Negative content can damage your reputation, while a positive footprint can help your career. You should think carefully before posting anything online.",
          explanation: "Everything online is potentially permanent and accessible.",
        },
        {
          questionText: "Which South African law specifically criminalizes cybercrime?",
          type: "multiple_choice",
          options: ["Cybercrimes Act (2020)", "POPIA", "ECT Act", "Copyright Act"],
          correctAnswer: "Cybercrimes Act (2020)",
          explanation: "The Cybercrimes Act 2020 is South Africa's dedicated cybercrime legislation.",
        },
      ],
    },
  },
];

// Combined export of all IT modules across all grades
export const allModules: ModuleSeed[] = [
  ...grade10Modules,
  ...grade11Modules,
  ...modules,
  ...chapterFocusModules,
  ...grade12ExamPrepModules,
];
