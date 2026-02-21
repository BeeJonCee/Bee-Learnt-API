import type { ModuleSeed } from "../types.js";

/**
 * Additional Grade 12 exam-prep modules grounded in:
 * - IT CAPS 2024 Section 3
 * - Grade 12 IT Tutoring Guide (Term 1)
 * - Information Technology P1 May/June 2025 paper + marking guideline
 */
export const grade12ExamPrepModules: ModuleSeed[] = [
  {
    key: "it12-exam-drills-section-a-2025",
    title: "Exam Drills 2025: Section A Programming Skills",
    description:
      "Target the recurring Paper 1 Section A patterns: selection, file loops, nested loops, and ASCII-based string tasks.",
    grade: 12,
    order: 15,
    capsTags: ["exam-prep", "section-a", "selection", "files", "strings", "loops"],
    lessons: [
      {
        title: "Pattern drills from the 2025 guideline",
        type: "text",
        order: 1,
        content:
          "# 2025 Section A Drill\nPractice the same logic patterns used in the marking grid:\n- itemIndex selection to set shape\n- color combination checks with AND/OR\n- file average using FileExists, Reset, EOF, Readln\n- nested loop number patterns\n- uppercase ASCII sums with Ord\n\nFocus on predictable, testable steps instead of writing everything at once.",
      },
      {
        title: "Marks-first coding structure",
        type: "text",
        order: 2,
        content:
          "# Marks-first structure\nUse this sequence in every button event:\n1. Read all inputs first\n2. Initialize counters/totals\n3. Apply condition or loop logic\n4. Format output exactly as required\n5. Handle edge cases (missing file, empty data)\n\nThis mirrors CAPS emphasis on algorithm development, precision, and validation of logic.",
      },
    ],
    quiz: {
      title: "Section A Exam Drill Quiz (2025)",
      description:
        "Practice exam logic patterns from the tutoring guide and the 2025 marking guideline.",
      difficulty: "medium",
      questions: [
        {
          questionText:
            "In a shape button task, which value is typically tested to decide between circle and rectangle?",
          type: "multiple_choice",
          options: ["RadioGroup ItemIndex", "Label Caption", "Form Width", "Memo Lines"],
          correctAnswer: "RadioGroup ItemIndex",
          explanation:
            "The 2025 pattern checks ItemIndex to map selection to stCircle or stRectangle.",
        },
        {
          questionText:
            "Write the color logic condition for purple when Red and Blue can appear in any order.",
          type: "short_answer",
          correctAnswer:
            "(c1 = 'Red' and c2 = 'Blue') or (c1 = 'Blue' and c2 = 'Red')",
          explanation: "The guideline explicitly awards marks for correct AND plus OR combinations.",
        },
        {
          questionText:
            "Why should FileExists be checked before Reset in a text-file question?",
          type: "short_answer",
          correctAnswer: "To avoid runtime errors when the file is missing.",
          explanation: "The marking grid includes checking file existence before file read loops.",
        },
        {
          questionText: "Which loop condition is correct for reading a text file line by line?",
          type: "multiple_choice",
          options: [
            "while not EOF(tFile) do",
            "while EOF(tFile) do",
            "for i := 1 to EOF(tFile) do",
            "repeat until FileExists(tFile)",
          ],
          correctAnswer: "while not EOF(tFile) do",
          explanation: "Readln repeats while the file has unread lines.",
        },
        {
          questionText:
            "In the nested pattern drill, the inner loop usually appends which value repeatedly?",
          type: "multiple_choice",
          options: ["The outer loop counter", "The inner loop counter only", "A random number", "The memo line count"],
          correctAnswer: "The outer loop counter",
          explanation:
            "The standard pattern builds lines like 1, 22, 333 using the outer counter value.",
        },
        {
          questionText:
            "How do you restrict an ASCII sum task to uppercase letters only?",
          type: "short_answer",
          correctAnswer: "Check if ch >= 'A' and ch <= 'Z' before adding Ord(ch).",
          explanation:
            "The 2025 guide uses an uppercase range check before including a character in the sum.",
        },
        {
          questionText: "Which formatting pattern shows a numeric average to exactly two decimals?",
          type: "multiple_choice",
          options: [
            "FormatFloat('0.00', avg)",
            "IntToStr(avg)",
            "Round(avg)",
            "Copy(avg, 1, 2)",
          ],
          correctAnswer: "FormatFloat('0.00', avg)",
          explanation: "The file average drill outputs values with two decimal places.",
        },
        {
          questionText:
            "Outline a robust algorithm for the button that reads numbers from a file and prints the average.",
          type: "essay",
          correctAnswer:
            "Check FileExists, AssignFile and Reset, initialize sum and count, loop while not EOF using Readln, update sum and count, close file, compute average if count > 0, and display with FormatFloat('0.00', avg).",
          explanation:
            "This full sequence aligns with the marks breakdown in the 2025 guideline.",
        },
      ],
    },
  },
  {
    key: "it12-exam-drills-section-b-2025",
    title: "Exam Drills 2025: Database Programming and SQL",
    description:
      "Train on SQL templates and Delphi dataset loops used in Paper 1 database questions.",
    grade: 12,
    order: 16,
    capsTags: ["exam-prep", "section-b", "sql", "database", "adoquery"],
    lessons: [
      {
        title: "SQL templates from marking patterns",
        type: "text",
        order: 1,
        content:
          "# Section B SQL templates\nBuild reusable SQL templates for:\n- SELECT + WHERE\n- ORDER BY descending date fields\n- YEAR(DateField) filters\n- GROUP BY with aggregate calculations\n- DELETE by exact identifier\n\nWrite SQL first, then wire it into Delphi controls.",
      },
      {
        title: "Dataset traversal and updates",
        type: "text",
        order: 2,
        content:
          "# Dataset loop discipline\nFor row-by-row updates:\n1. Call First\n2. Loop while not EOF\n3. Test condition\n4. Edit, assign field, Post\n5. Next\n\nThis pattern is explicitly rewarded in the database manipulation section.",
      },
    ],
    quiz: {
      title: "Section B SQL and Dataset Quiz (2025)",
      description:
        "Prepare for 2025-style SQL statements and database manipulation logic.",
      difficulty: "medium",
      questions: [
        {
          questionText:
            "Which SQL query correctly returns all companies where Country is USA?",
          type: "multiple_choice",
          options: [
            "SELECT * FROM tblCompanies WHERE Country = 'USA'",
            "SELECT Country FROM tblCompanies = 'USA'",
            "DELETE FROM tblCompanies WHERE Country = 'USA'",
            "SELECT * FROM tblCompanies ORDER BY USA",
          ],
          correctAnswer: "SELECT * FROM tblCompanies WHERE Country = 'USA'",
          explanation: "This mirrors the first SQL template in the 2025 marking grid.",
        },
        {
          questionText:
            "Write a valid SQL filter to get games released from 2019 onward.",
          type: "short_answer",
          correctAnswer: "SELECT ... FROM tblGames WHERE YEAR(DateReleased) >= 2019",
          explanation: "The guideline accepts YEAR(DateReleased) based filtering.",
        },
        {
          questionText:
            "Which clause sorts game results by release date from newest to oldest?",
          type: "multiple_choice",
          options: [
            "ORDER BY DateReleased DESC",
            "GROUP BY DateReleased DESC",
            "WHERE DateReleased DESC",
            "SORT DateReleased DESC",
          ],
          correctAnswer: "ORDER BY DateReleased DESC",
          explanation: "Descending order is required for newest-first output.",
        },
        {
          questionText:
            "What is the main purpose of GROUP BY in SQL?",
          type: "short_answer",
          correctAnswer:
            "To group rows so aggregate functions like SUM, COUNT, and AVG can be calculated per group.",
          explanation: "Aggregate reporting questions depend on grouped results.",
        },
        {
          questionText:
            "Write the SQL command to remove a game titled Apex Legends from tblGames.",
          type: "short_answer",
          correctAnswer: "DELETE FROM tblGames WHERE GameTitle = 'Apex Legends'",
          explanation: "The 2025 marking grid includes this exact delete pattern.",
        },
        {
          questionText:
            "What is the correct Delphi traversal sequence for updating selected rows?",
          type: "multiple_choice",
          options: [
            "First, while not EOF, Edit/Post when needed, Next",
            "Next, First, Edit, EOF",
            "Open, Append, Rewrite, Reset",
            "Sort, Filter, Delete, Exit",
          ],
          correctAnswer: "First, while not EOF, Edit/Post when needed, Next",
          explanation: "The grid allocates marks for this loop sequence.",
        },
        {
          questionText:
            "Why are Edit and Post paired in a dataset update routine?",
          type: "short_answer",
          correctAnswer:
            "Edit puts the record into edit mode and Post saves the field changes to the dataset.",
          explanation: "Without Post, updates are not committed.",
        },
        {
          questionText:
            "Explain how you would solve a question that requires SQL selection plus a second table lookup for display.",
          type: "essay",
          correctAnswer:
            "Run the first dataset query, loop through matching records, use the key field to find related rows in the second table, combine values into the required output format, and move both datasets correctly with Next until EOF.",
          explanation:
            "This matches the two-stage data lookup pattern in Section B manipulation tasks.",
        },
      ],
    },
  },
  {
    key: "it12-exam-drills-section-cd-2025",
    title: "Exam Drills 2025: OOP and Problem Solving",
    description:
      "Practice class design, object usage, and algorithmic problem-solving patterns such as pangram checks.",
    grade: 12,
    order: 17,
    capsTags: ["exam-prep", "section-c", "section-d", "oop", "problem-solving"],
    lessons: [
      {
        title: "Object-oriented coding patterns",
        type: "text",
        order: 1,
        content:
          "# OOP marks patterns\nUse a repeatable class template:\n- private fields\n- constructor to initialize fields\n- methods for state logic\n- toString output formatter\n\nIn button events, instantiate correctly and call methods for compatibility and popularity checks.",
      },
      {
        title: "Algorithmic checks and decomposition",
        type: "text",
        order: 2,
        content:
          "# Problem-solving pattern\nFor functions like isPangram:\n1. Normalize case\n2. Track each required symbol (A to Z)\n3. Scan input once or use a frequency structure\n4. Return true only if all required letters appear\n\nThen integrate it into UI output loops with clear Yes/No reporting.",
      },
    ],
    quiz: {
      title: "Section C and D OOP Problem-Solving Quiz (2025)",
      description:
        "Reinforce 2025 exam patterns for class methods and algorithmic checks.",
      difficulty: "hard",
      questions: [
        {
          questionText: "What is the main role of a constructor in a Delphi class?",
          type: "short_answer",
          correctAnswer:
            "To initialize object fields with starting values when an object is created.",
          explanation: "Section C awards constructor marks for correct parameter-to-field assignment.",
        },
        {
          questionText:
            "In an onlineStatus method, what should be returned when fOnline is true?",
          type: "multiple_choice",
          options: ["Yes", "Online", "1", "True status"],
          correctAnswer: "Yes",
          explanation: "The marking grid pattern returns Yes/No text values.",
        },
        {
          questionText:
            "If downloads are 650000 and the game is online, what popularity label is expected in the 2025 logic?",
          type: "multiple_choice",
          options: ["Very popular", "Popular", "Not popular", "Not an online game"],
          correctAnswer: "Very popular",
          explanation:
            "The threshold pattern maps higher online download counts to Very popular.",
        },
        {
          questionText:
            "What should updateDownloadCount(iAdd) do to the internal counter?",
          type: "short_answer",
          correctAnswer: "Set fDownloadCount := fDownloadCount + iAdd.",
          explanation: "The method increments existing state by the provided value.",
        },
        {
          questionText:
            "Why is toString useful in Section C button tasks?",
          type: "short_answer",
          correctAnswer:
            "It formats object state into one readable output string for quick display and verification.",
          explanation: "Many tasks require showing combined object details after updates.",
        },
        {
          questionText: "What is a pangram?",
          type: "short_answer",
          correctAnswer: "A sentence that contains every letter of the alphabet at least once.",
          explanation: "Section D tests this as a standalone algorithmic function.",
        },
        {
          questionText:
            "Which approach best handles uppercase and lowercase in a pangram function?",
          type: "multiple_choice",
          options: [
            "Normalize text case before checking A-Z coverage",
            "Check only uppercase letters and ignore lowercase",
            "Reject any lowercase input",
            "Count words instead of letters",
          ],
          correctAnswer: "Normalize text case before checking A-Z coverage",
          explanation:
            "Case normalization ensures both uppercase and lowercase letters are tracked correctly.",
        },
        {
          questionText:
            "Describe a complete algorithm for isPangram and how button output should use it.",
          type: "essay",
          correctAnswer:
            "Initialize a structure to track 26 letters, normalize the input, loop through characters and mark present letters, then verify all 26 are present. Return true only when coverage is complete. In the button event, loop through sentences, call isPangram for each sentence, and print sentence plus Yes or No output.",
          explanation:
            "This combines function design with the section output routine expected in the exam.",
        },
      ],
    },
  },
];
