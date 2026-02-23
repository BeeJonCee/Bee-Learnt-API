import type { ModuleSeed } from "../types.js";

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function buildChapterDiagram(input: {
  title: string;
  subtitle: string;
  badge: string;
  start: string;
  end: string;
  accent: string;
}): string {
  const svg = `
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="360" viewBox="0 0 1200 360" role="img" aria-label="${escapeXml(
    input.title,
  )}">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${input.start}" />
      <stop offset="100%" stop-color="${input.end}" />
    </linearGradient>
  </defs>
  <rect x="0" y="0" width="1200" height="360" rx="24" fill="url(#bg)" />
  <circle cx="1040" cy="58" r="130" fill="rgba(255,255,255,0.10)" />
  <circle cx="1150" cy="300" r="200" fill="rgba(255,255,255,0.08)" />
  <rect x="64" y="52" width="244" height="42" rx="21" fill="rgba(15,23,42,0.40)" />
  <text x="186" y="79" text-anchor="middle" fill="#e5e7eb" font-size="18" font-family="Arial, sans-serif" font-weight="700">
    ${escapeXml(input.badge)}
  </text>
  <text x="64" y="166" fill="#ffffff" font-size="46" font-family="Arial, sans-serif" font-weight="700">
    ${escapeXml(input.title)}
  </text>
  <text x="64" y="216" fill="#e5e7eb" font-size="28" font-family="Arial, sans-serif">
    ${escapeXml(input.subtitle)}
  </text>
  <g transform="translate(930,170)">
    <rect x="-12" y="-52" width="20" height="112" rx="9" fill="#ffffff" opacity="0.9" />
    <rect x="22" y="-20" width="20" height="80" rx="9" fill="#ffffff" opacity="0.9" />
    <rect x="56" y="-64" width="20" height="124" rx="9" fill="#ffffff" opacity="0.9" />
    <circle cx="100" cy="-40" r="8" fill="${input.accent}" />
    <circle cx="128" cy="-12" r="8" fill="${input.accent}" />
    <circle cx="156" cy="16" r="8" fill="${input.accent}" />
    <line x1="100" y1="-40" x2="128" y2="-12" stroke="${input.accent}" stroke-width="3" />
    <line x1="128" y1="-12" x2="156" y2="16" stroke="${input.accent}" stroke-width="3" />
  </g>
</svg>`;

  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

function buildWorksheetDiagram(input: {
  title: string;
  subtitle: string;
  steps: string[];
  start: string;
  end: string;
  accent: string;
}): string {
  const rows = input.steps
    .slice(0, 5)
    .map((step, index) => {
      const y = 116 + index * 42;
      const number = index + 1;
      return `
  <g>
    <circle cx="88" cy="${y - 8}" r="15" fill="${input.accent}" />
    <text x="88" y="${y - 3}" text-anchor="middle" fill="#0b1020" font-size="14" font-family="Arial, sans-serif" font-weight="700">${number}</text>
    <rect x="116" y="${y - 24}" width="716" height="30" rx="10" fill="rgba(255,255,255,0.82)" />
    <text x="132" y="${y - 4}" fill="#0b1020" font-size="16" font-family="Arial, sans-serif">${escapeXml(step)}</text>
  </g>`;
    })
    .join("");

  const svg = `
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="420" viewBox="0 0 1200 420" role="img" aria-label="${escapeXml(
    input.title,
  )}">
  <defs>
    <linearGradient id="sheet" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${input.start}" />
      <stop offset="100%" stop-color="${input.end}" />
    </linearGradient>
  </defs>
  <rect x="0" y="0" width="1200" height="420" rx="24" fill="url(#sheet)" />
  <rect x="52" y="42" width="858" height="334" rx="18" fill="rgba(15,23,42,0.28)" />
  <text x="78" y="88" fill="#ffffff" font-size="30" font-family="Arial, sans-serif" font-weight="700">${escapeXml(
    input.title,
  )}</text>
  <text x="78" y="110" fill="#dbeafe" font-size="16" font-family="Arial, sans-serif">${escapeXml(
    input.subtitle,
  )}</text>
  ${rows}
  <g transform="translate(946,64)">
    <rect x="0" y="0" width="206" height="296" rx="16" fill="rgba(15,23,42,0.34)" />
    <text x="103" y="36" text-anchor="middle" fill="#f8fafc" font-size="18" font-family="Arial, sans-serif" font-weight="700">Tips</text>
    <circle cx="26" cy="74" r="7" fill="${input.accent}" />
    <text x="42" y="80" fill="#e2e8f0" font-size="15" font-family="Arial, sans-serif">Show every step.</text>
    <circle cx="26" cy="124" r="7" fill="${input.accent}" />
    <text x="42" y="130" fill="#e2e8f0" font-size="15" font-family="Arial, sans-serif">Label key terms.</text>
    <circle cx="26" cy="174" r="7" fill="${input.accent}" />
    <text x="42" y="180" fill="#e2e8f0" font-size="15" font-family="Arial, sans-serif">Check units/data.</text>
    <circle cx="26" cy="224" r="7" fill="${input.accent}" />
    <text x="42" y="230" fill="#e2e8f0" font-size="15" font-family="Arial, sans-serif">Explain your choice.</text>
  </g>
</svg>`;

  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

const grade10Chapter1Diagram = buildChapterDiagram({
  title: "Grade 10 Chapter 1",
  subtitle: "Computer model, hardware, software, and IPO flow",
  badge: "CHAPTER 1 ACTIVITY LAB",
  start: "#0f172a",
  end: "#1d4ed8",
  accent: "#facc15",
});

const grade10Chapter2Diagram = buildChapterDiagram({
  title: "Grade 10 Chapter 2",
  subtitle: "Data representation, files, and social implications",
  badge: "CHAPTER 2 ACTIVITY LAB",
  start: "#082f49",
  end: "#0e7490",
  accent: "#67e8f9",
});

const grade11Chapter1Diagram = buildChapterDiagram({
  title: "Grade 11 Chapter 1",
  subtitle: "Motherboard, cache, memory, and performance",
  badge: "HARDWARE ACTIVITY LAB",
  start: "#111827",
  end: "#4338ca",
  accent: "#fbbf24",
});

const grade11Chapter2Diagram = buildChapterDiagram({
  title: "Grade 11 Chapter 2",
  subtitle: "Operating systems, compilers, processing, virtualization",
  badge: "SOFTWARE ACTIVITY LAB",
  start: "#1f2937",
  end: "#0f766e",
  accent: "#2dd4bf",
});

const grade12Chapter1Diagram = buildChapterDiagram({
  title: "Grade 12 Chapter 1",
  subtitle: "Data collection, warehousing, mining, and quality",
  badge: "DB MANAGEMENT LAB",
  start: "#312e81",
  end: "#7c3aed",
  accent: "#fb7185",
});

const grade12Chapter2Diagram = buildChapterDiagram({
  title: "Grade 12 Chapter 2",
  subtitle: "Database design, anomalies, and normalization",
  badge: "DB DESIGN LAB",
  start: "#3f1d2e",
  end: "#be185d",
  accent: "#fda4af",
});

const grade10Chapter1WorksheetDiagram = buildWorksheetDiagram({
  title: "Grade 10 Chapter 1 Activity Sheet",
  subtitle: "Computing basics checklist",
  steps: [
    "Draw IPO flow and label each stage.",
    "Classify 6 hardware and software examples.",
    "Compare two computer types using one table.",
    "Write one benefit and one risk with an example.",
    "Turn raw data into information using a mini scenario.",
  ],
  start: "#1e293b",
  end: "#2563eb",
  accent: "#fde047",
});

const grade10Chapter2WorksheetDiagram = buildWorksheetDiagram({
  title: "Grade 10 Chapter 2 Activity Sheet",
  subtitle: "Data representation and file skills checklist",
  steps: [
    "Define data, information, and knowledge clearly.",
    "Convert decimal numbers to binary with workings.",
    "Convert hexadecimal values to decimal and binary.",
    "Map a folder tree and label file extensions.",
    "Explain one privacy and one copyright risk.",
  ],
  start: "#155e75",
  end: "#0891b2",
  accent: "#67e8f9",
});

const grade11Chapter1WorksheetDiagram = buildWorksheetDiagram({
  title: "Grade 11 Chapter 1 Activity Sheet",
  subtitle: "Hardware and performance checklist",
  steps: [
    "Label motherboard parts and data buses.",
    "Explain cache levels L1, L2, and L3.",
    "Compare RAM, ROM, SSD, and HDD roles.",
    "Find one bottleneck in a slow PC scenario.",
    "Recommend one upgrade and justify it.",
  ],
  start: "#1f2937",
  end: "#4338ca",
  accent: "#fbbf24",
});

const grade11Chapter2WorksheetDiagram = buildWorksheetDiagram({
  title: "Grade 11 Chapter 2 Activity Sheet",
  subtitle: "Software systems checklist",
  steps: [
    "Classify OS types with real examples.",
    "Compare compiler and interpreter outputs.",
    "Match tasks to multitasking/threading/processes.",
    "Draw a host and guest VM stack.",
    "State one virtualization benefit and one limitation.",
  ],
  start: "#1f2937",
  end: "#0f766e",
  accent: "#2dd4bf",
});

const grade12Chapter1WorksheetDiagram = buildWorksheetDiagram({
  title: "Grade 12 Chapter 1 Activity Sheet",
  subtitle: "Database management pipeline checklist",
  steps: [
    "Capture transaction data from two input channels.",
    "Separate operational DB and warehouse use.",
    "Pick one mining question and expected insight.",
    "List metadata fields needed for trust.",
    "Add one rollback or audit safety control.",
  ],
  start: "#4c1d95",
  end: "#7c3aed",
  accent: "#fb7185",
});

const grade12Chapter2WorksheetDiagram = buildWorksheetDiagram({
  title: "Grade 12 Chapter 2 Activity Sheet",
  subtitle: "Database design and normalization checklist",
  steps: [
    "Spot insertion, deletion, and update anomalies.",
    "Split one overloaded table into linked tables.",
    "Mark primary, foreign, and alternate keys.",
    "Verify each table has one clear purpose.",
    "Explain why redundancy is now reduced.",
  ],
  start: "#500724",
  end: "#be185d",
  accent: "#fda4af",
});

export const chapterFocusModules: ModuleSeed[] = [
  {
    key: "it10-ch1-activity-lab",
    title: "Grade 10 Chapter 1 Activity Lab",
    description:
      "Chapter 1 skills with guided activities: computer model, hardware/software, types of computers, and data flow.",
    grade: 10,
    order: 13,
    capsTags: ["grade10", "chapter1", "computing-basics", "activity-lab"],
    lessons: [
      {
        title: "Chapter 1 outcomes and concept map",
        type: "text",
        order: 1,
        content:
          "# Chapter 1 Focus\n- General model of a computer\n- Hardware and software interdependence\n- Types of computers and where each fits\n- Advantages and risks of computer use\n- Data vs information and IPO thinking\n\nGoal: explain each concept clearly before writing code-based solutions.",
      },
      {
        title: "Activity walkthrough (1.1 to 1.5)",
        type: "text",
        order: 2,
        content:
          "# Activity Plan\n1. Activity 1.1: Define ICT vs IT and draw IPO model.\n2. Activity 1.2: Match hardware/software and classify system vs application software.\n3. Activity 1.3: Compare desktop, laptop, smartphone, tablet, server, and embedded computers.\n4. Activity 1.4: Evaluate advantages and disadvantages in real scenarios.\n5. Activity 1.5: Build data-information examples and IPO tables.\n\nUse short written explanations before selecting final answers.",
      },
      {
        title: "Visual guide: computer pipeline",
        type: "diagram",
        order: 3,
        content:
          "Use this visual as a memory anchor for input-processing-output-storage and concept linking.",
        diagramUrl: grade10Chapter1Diagram,
      },
      {
        title: "Activity sheet visual: Chapter 1 checklist",
        type: "diagram",
        order: 4,
        content:
          "Use this worksheet visual while completing assignments so each answer includes the required chapter evidence.",
        diagramUrl: grade10Chapter1WorksheetDiagram,
      },
    ],
    assignmentTemplates: [
      {
        title: "Grade 10 Chapter 1 Practical Task - IPO Model Build",
        description:
          "Step 1: Draw one IPO flow diagram with clear labels for Input, Process, Output, and Storage.\nStep 2: Add one real-life example for each IPO stage.\nStep 3: List 4 hardware components and 4 software examples used in your flow.\nStep 4: Write 5 short sentences explaining how hardware and software depend on each other.\nStep 5: Submit one page with neat labels and your name/grade.",
        priority: "high",
      },
      {
        title: "Grade 10 Chapter 1 Guided Worksheet - Computer Types",
        description:
          "Step 1: Create a table with desktop, laptop, smartphone, tablet, server, and embedded device.\nStep 2: For each type, write one use case, one strength, and one limitation.\nStep 3: Add one sentence that compares any two types.\nStep 4: Circle the best type for school lab work and explain why.\nStep 5: Review spelling of key terms before submit.",
        priority: "medium",
      },
      {
        title: "Grade 10 Chapter 1 Exam-Style Drill - Data to Information",
        description:
          "Step 1: Read the scenario and identify raw data items.\nStep 2: Show how data is processed into useful information.\nStep 3: Fill in a mini IPO table with at least 3 rows.\nStep 4: Answer in full sentences and show your reasoning.\nStep 5: Check that each answer matches the question verb exactly.",
        priority: "high",
      },
      {
        title: "Grade 10 Chapter 1 Memo Reflection - Fix and Explain",
        description:
          "Step 1: Compare your answers to the memo.\nStep 2: Find your top 3 mistakes.\nStep 3: Rewrite each incorrect answer correctly.\nStep 4: Under each fix, explain why your first answer was wrong.\nStep 5: End with one action you will use in the next chapter task.",
        priority: "medium",
      },
    ],
    quiz: {
      title: "Grade 10 Chapter 1 Quiz",
      description: "Quick chapter check from Activity 1.1 to 1.5 patterns.",
      difficulty: "easy",
      questions: [
        {
          questionText: "What does IPO stand for in computer processing?",
          type: "multiple_choice",
          options: ["Input, Process, Output", "Input, Program, Output", "Internet, Processing, Operation", "Internal, Public, Output"],
          correctAnswer: "Input, Process, Output",
          explanation: "IPO describes how input data is processed to produce output.",
        },
        {
          questionText: "Explain the difference between hardware and software.",
          type: "short_answer",
          correctAnswer: "Hardware is the physical device components, while software is the instructions/programs that run on the hardware.",
          explanation: "Both are interdependent for a computer system to work.",
        },
        {
          questionText: "Which memory type is temporary and cleared when power is off?",
          type: "multiple_choice",
          options: ["RAM", "ROM", "SSD", "Optical disk"],
          correctAnswer: "RAM",
          explanation: "RAM is volatile memory used for active tasks.",
        },
        {
          questionText: "Name one advantage and one risk of computer use.",
          type: "short_answer",
          correctAnswer: "Advantage: faster productivity and communication. Risk: malware/security threats or privacy loss.",
          explanation: "Chapter 1 activities balance benefits and drawbacks.",
        },
        {
          questionText: "Describe the full data journey from user input to stored output in your own words.",
          type: "essay",
          correctAnswer: "A user provides input, the system stores it in memory, processing rules transform it into useful output, and the final data can be saved for future use.",
          explanation: "This is the core processing model used throughout IT.",
        },
      ],
    },
  },
  {
    key: "it10-ch2-activity-lab",
    title: "Grade 10 Chapter 2 Activity Lab",
    description:
      "Chapter 2 drills for number systems, primitive data types, file management, and social implications.",
    grade: 10,
    order: 14,
    capsTags: ["grade10", "chapter2", "data-representation", "activity-lab"],
    lessons: [
      {
        title: "Chapter 2 outcomes and concept map",
        type: "text",
        order: 1,
        content:
          "# Chapter 2 Focus\n- Data, information, and knowledge relationships\n- Binary/decimal/hexadecimal conversions\n- ASCII and primitive data types\n- File/folder management and extensions\n- Social implications: privacy, copyright, digital divide\n\nGoal: solve representation tasks and explain social impacts clearly.",
      },
      {
        title: "Activity walkthrough (2.1 to 2.7)",
        type: "text",
        order: 2,
        content:
          "# Activity Plan\n1. Activity 2.1: Define data, information, and knowledge.\n2. Activity 2.2 and 2.3: Conversion drills across decimal, binary, and hexadecimal.\n3. Activity 2.4: Data types and character representation.\n4. Activity 2.5 and 2.6: File pathing, file management, and extension usage.\n5. Activity 2.7: Ethical/legal social implications in ICT.\n\nWork each conversion step line-by-line and verify with partner checks.",
      },
      {
        title: "Visual guide: binary and files board",
        type: "diagram",
        order: 3,
        content:
          "Use this visual to remember conversion logic, file structures, and social issue checkpoints.",
        diagramUrl: grade10Chapter2Diagram,
      },
      {
        title: "Activity sheet visual: Chapter 2 checklist",
        type: "diagram",
        order: 4,
        content:
          "Use this worksheet visual to track each conversion, file-path task, and social-implication response.",
        diagramUrl: grade10Chapter2WorksheetDiagram,
      },
    ],
    assignmentTemplates: [
      {
        title: "Grade 10 Chapter 2 Practical Task - Number Conversion Pack",
        description:
          "Step 1: Convert 5 decimal numbers to binary and show all place-value workings.\nStep 2: Convert 5 binary numbers to decimal and verify each total.\nStep 3: Convert 3 hexadecimal values to decimal and binary.\nStep 4: Highlight one mistake you almost made and how you avoided it.\nStep 5: Submit clean workings, not only final answers.",
        priority: "high",
      },
      {
        title: "Grade 10 Chapter 2 Guided Worksheet - Files and Folders",
        description:
          "Step 1: Draw a folder tree for a school project with at least 3 levels.\nStep 2: Add 8 file names with correct extensions (.txt, .csv, .jpg, .exe, etc.).\nStep 3: Explain what each extension is used for.\nStep 4: Write one rule for naming files clearly.\nStep 5: Check that each file is in a logical folder.",
        priority: "medium",
      },
      {
        title: "Grade 10 Chapter 2 Exam-Style Drill - Ethics and Law",
        description:
          "Step 1: Read two short ICT scenarios.\nStep 2: Identify whether each case is legal, illegal, ethical, or unethical.\nStep 3: Name the key risk (privacy, copyright, or digital divide).\nStep 4: Give one prevention action per scenario.\nStep 5: Use complete sentences with chapter terminology.",
        priority: "high",
      },
      {
        title: "Grade 10 Chapter 2 Memo Reflection - Conversion Corrections",
        description:
          "Step 1: Compare your conversion answers with the memo.\nStep 2: Correct at least 4 wrong lines and show fixed steps.\nStep 3: Write one sentence per correction explaining the error type.\nStep 4: Re-answer one social-implication question with improved depth.\nStep 5: Submit the corrected version as your final copy.",
        priority: "medium",
      },
    ],
    quiz: {
      title: "Grade 10 Chapter 2 Quiz",
      description: "Chapter 2 checks for data representation and file skills.",
      difficulty: "medium",
      questions: [
        {
          questionText: "How many bytes are in 1 kilobyte (binary definition)?",
          type: "multiple_choice",
          options: ["1024", "1000", "512", "2048"],
          correctAnswer: "1024",
          explanation: "The chapter uses binary-based storage units.",
        },
        {
          questionText: "Convert binary 101101 to decimal.",
          type: "short_answer",
          correctAnswer: "45",
          explanation: "32 + 8 + 4 + 1 = 45.",
        },
        {
          questionText: "Why are file extensions important?",
          type: "short_answer",
          correctAnswer: "They indicate file type so software and users can open/manage files correctly.",
          explanation: "Extensions help systems identify expected format and behavior.",
        },
        {
          questionText: "Which issue describes unequal access to technology and internet?",
          type: "multiple_choice",
          options: ["Digital divide", "Defragmentation", "Virtualization", "Thread starvation"],
          correctAnswer: "Digital divide",
          explanation: "Digital divide is a key social implication topic in Chapter 2.",
        },
        {
          questionText: "Explain one legal and one ethical concern linked to digital content sharing.",
          type: "essay",
          correctAnswer: "Legal concern: copyright infringement through piracy. Ethical concern: sharing content without creator permission harms ownership rights and fair use.",
          explanation: "Chapter 2 social implications include copyright and responsible use.",
        },
      ],
    },
  },
  {
    key: "it11-ch1-hardware-lab",
    title: "Grade 11 Chapter 1 Hardware Lab",
    description:
      "Chapter 1 hardware drills: motherboard architecture, cache layers, memory behavior, and performance analysis.",
    grade: 11,
    order: 13,
    capsTags: ["grade11", "chapter1", "hardware", "activity-lab"],
    lessons: [
      {
        title: "Chapter 1 hardware concept map",
        type: "text",
        order: 1,
        content:
          "# Chapter 1 Focus\n- Motherboard role and key slots\n- Data flow via buses and point-to-point links\n- Cache and memory hierarchy\n- RAM/ROM/storage differences\n- Hardware performance bottlenecks\n\nGoal: diagnose hardware behavior using structure + function reasoning.",
      },
      {
        title: "Activity walkthrough (1.1 to 1.4)",
        type: "text",
        order: 2,
        content:
          "# Activity Plan\n1. Activity 1.1 and 1.2: motherboard, slots, ports, BIOS, and expansion cards.\n2. Activity 1.3: memory and cache interpretation tasks.\n3. Activity 1.4: performance bottleneck diagnosis and upgrade decisions.\n\nUse evidence from specs before selecting answers.",
      },
      {
        title: "Visual guide: motherboard and memory map",
        type: "diagram",
        order: 3,
        content:
          "Use this visual to map CPU-cache-RAM-storage interactions and performance effects.",
        diagramUrl: grade11Chapter1Diagram,
      },
      {
        title: "Activity sheet visual: Hardware checklist",
        type: "diagram",
        order: 4,
        content:
          "Use this worksheet visual to verify hardware labels, cache logic, and bottleneck diagnosis steps.",
        diagramUrl: grade11Chapter1WorksheetDiagram,
      },
    ],
    assignmentTemplates: [
      {
        title: "Grade 11 Chapter 1 Practical Task - Motherboard Mapping",
        description:
          "Step 1: Label a motherboard diagram with CPU socket, RAM slots, storage ports, and expansion slots.\nStep 2: Draw arrows to show data flow paths.\nStep 3: Explain BIOS and bus roles in 4 short points.\nStep 4: Add one example where a wrong slot choice causes failure.\nStep 5: Submit annotated diagram with clear labels.",
        priority: "high",
      },
      {
        title: "Grade 11 Chapter 1 Guided Worksheet - Cache and Memory",
        description:
          "Step 1: Define cache, RAM, ROM, HDD, and SSD in your own words.\nStep 2: Rank them from fastest to slowest access.\nStep 3: Explain why cache improves CPU performance.\nStep 4: Match each memory/storage type to one practical task.\nStep 5: Check every definition for correct terminology.",
        priority: "medium",
      },
      {
        title: "Grade 11 Chapter 1 Exam-Style Drill - Performance Diagnosis",
        description:
          "Step 1: Read the slow-computer scenario carefully.\nStep 2: Identify likely bottlenecks (CPU, RAM, storage, network).\nStep 3: Choose the best upgrade with one reason.\nStep 4: Reject one bad upgrade option with explanation.\nStep 5: Present answer as problem -> evidence -> fix.",
        priority: "high",
      },
      {
        title: "Grade 11 Chapter 1 Memo Reflection - Hardware Fixes",
        description:
          "Step 1: Compare your answers to the memo.\nStep 2: Rewrite all incorrect labels and performance conclusions.\nStep 3: Add one sentence per correction showing the correct concept.\nStep 4: Note one revision strategy for next hardware task.\nStep 5: Submit corrections with section headings.",
        priority: "medium",
      },
    ],
    quiz: {
      title: "Grade 11 Chapter 1 Hardware Quiz",
      description: "Hardware and performance checks based on chapter activities.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the core role of the motherboard?",
          type: "short_answer",
          correctAnswer: "It physically and electrically connects components and enables communication between them.",
          explanation: "The motherboard is the communication hub of the system.",
        },
        {
          questionText: "What is the main purpose of CPU cache?",
          type: "multiple_choice",
          options: ["Store frequently needed data close to CPU", "Replace long-term storage", "Act as internet firewall", "Power the motherboard"],
          correctAnswer: "Store frequently needed data close to CPU",
          explanation: "Cache reduces delay between CPU and slower memory layers.",
        },
        {
          questionText: "Name two factors that strongly affect computer performance.",
          type: "short_answer",
          correctAnswer: "CPU capability and RAM capacity/speed.",
          explanation: "Storage speed and network speed also influence performance in specific tasks.",
        },
        {
          questionText: "Which memory is non-volatile and commonly stores BIOS instructions?",
          type: "multiple_choice",
          options: ["ROM", "RAM", "CPU cache", "VRAM only"],
          correctAnswer: "ROM",
          explanation: "ROM holds firmware needed at startup.",
        },
        {
          questionText: "A computer is slow when opening apps and loading OS files. Explain a likely bottleneck and fix.",
          type: "essay",
          correctAnswer: "A slow storage device can bottleneck startup and app loads. Upgrading from HDD to SSD and ensuring enough RAM improves responsiveness.",
          explanation: "Performance diagnosis combines multiple hardware factors.",
        },
      ],
    },
  },
  {
    key: "it11-ch2-software-lab",
    title: "Grade 11 Chapter 2 Software Lab",
    description:
      "Chapter 2 software drills: operating systems, compiler/interpreter behavior, processing techniques, and virtualization.",
    grade: 11,
    order: 14,
    capsTags: ["grade11", "chapter2", "software", "activity-lab"],
    lessons: [
      {
        title: "Chapter 2 software concept map",
        type: "text",
        order: 1,
        content:
          "# Chapter 2 Focus\n- Types of operating systems and where each is used\n- Compilers vs interpreters\n- Multitasking, multithreading, multiprocessing\n- Virtualization and virtual machine use cases\n\nGoal: choose software architecture based on purpose and constraints.",
      },
      {
        title: "Activity walkthrough (2.1 to 2.5)",
        type: "text",
        order: 2,
        content:
          "# Activity Plan\n1. Activity 2.1 and 2.2: software and OS classification tasks.\n2. Activity 2.3: compiler/interpreter comparison and coding pipeline.\n3. Activity 2.4: processing-technique scenario analysis.\n4. Activity 2.5: virtualization use-case evaluation.\n\nFocus on justification, not only final choice.",
      },
      {
        title: "Visual guide: software execution stack",
        type: "diagram",
        order: 3,
        content:
          "Use this visual to compare execution pipelines and virtualization layers.",
        diagramUrl: grade11Chapter2Diagram,
      },
      {
        title: "Activity sheet visual: Software checklist",
        type: "diagram",
        order: 4,
        content:
          "Use this worksheet visual to complete OS, compiler/interpreter, and virtualization tasks in order.",
        diagramUrl: grade11Chapter2WorksheetDiagram,
      },
    ],
    assignmentTemplates: [
      {
        title: "Grade 11 Chapter 2 Practical Task - Software Stack Build",
        description:
          "Step 1: Draw a stack from source code to CPU execution.\nStep 2: Show compiler path and interpreter path side-by-side.\nStep 3: Add one use case where each path is preferred.\nStep 4: Include one common error learners make and correction.\nStep 5: Submit one labeled diagram plus short explanation.",
        priority: "high",
      },
      {
        title: "Grade 11 Chapter 2 Guided Worksheet - OS and Processing",
        description:
          "Step 1: Classify at least 5 systems by OS type.\nStep 2: Define multitasking, multithreading, and multiprocessing.\nStep 3: Match each processing model to one practical scenario.\nStep 4: Explain one tradeoff for each model.\nStep 5: Check your examples are realistic and specific.",
        priority: "medium",
      },
      {
        title: "Grade 11 Chapter 2 Exam-Style Drill - Virtualization Case",
        description:
          "Step 1: Read a school-lab virtualization scenario.\nStep 2: Decide if virtualization is suitable and why.\nStep 3: List two benefits and two limitations.\nStep 4: Recommend host and guest setup briefly.\nStep 5: Present answer using bullet points with evidence.",
        priority: "high",
      },
      {
        title: "Grade 11 Chapter 2 Memo Reflection - Software Reasoning",
        description:
          "Step 1: Mark wrong answers from your worksheet and drill.\nStep 2: Rewrite each answer with improved logic.\nStep 3: Underline chapter keywords in each corrected answer.\nStep 4: Write one sentence on how you will avoid the same mistake.\nStep 5: Submit corrected responses as a final reflection.",
        priority: "medium",
      },
    ],
    quiz: {
      title: "Grade 11 Chapter 2 Software Quiz",
      description: "Software concepts and execution model checks from chapter activities.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the main difference between a compiler and an interpreter?",
          type: "short_answer",
          correctAnswer: "A compiler translates full program code before execution, while an interpreter translates and runs code line by line.",
          explanation: "This affects startup behavior and error handling.",
        },
        {
          questionText: "Which operating system type is designed for dedicated devices with fixed tasks?",
          type: "multiple_choice",
          options: ["Embedded OS", "Desktop stand-alone OS only", "Spreadsheet engine", "Browser runtime"],
          correctAnswer: "Embedded OS",
          explanation: "Embedded systems target single-purpose hardware scenarios.",
        },
        {
          questionText: "Define multitasking in one sentence.",
          type: "short_answer",
          correctAnswer: "Multitasking is the OS capability to switch between tasks quickly so multiple applications appear to run simultaneously.",
          explanation: "It is core to modern operating-system behavior.",
        },
        {
          questionText: "Why might a team use a virtual machine during software testing?",
          type: "multiple_choice",
          options: ["To isolate risky software and protect host system", "To physically upgrade RAM", "To replace all networking hardware", "To remove need for any OS"],
          correctAnswer: "To isolate risky software and protect host system",
          explanation: "Virtualization creates safe test boundaries.",
        },
        {
          questionText: "Compare multitasking, multithreading, and multiprocessing with one practical example for each.",
          type: "essay",
          correctAnswer: "Multitasking: running browser and editor together. Multithreading: one app rendering UI while processing data in parallel threads. Multiprocessing: separate CPU cores executing different processes concurrently.",
          explanation: "The chapter emphasizes clear distinction of processing models.",
        },
      ],
    },
  },
  {
    key: "it12-ch1-database-management-lab",
    title: "Grade 12 Chapter 1 Database Management Lab",
    description:
      "Chapter 1 database management drills: collection methods, warehousing, mining, and data governance quality checks.",
    grade: 12,
    order: 18,
    capsTags: ["grade12", "chapter1", "database-management", "activity-lab"],
    lessons: [
      {
        title: "Chapter 1 database management concept map",
        type: "text",
        order: 1,
        content:
          "# Chapter 1 Focus\n- Data capture and transaction handling\n- Data warehouse purpose and architecture\n- Data mining for trends and decisions\n- Data care and management controls\n\nGoal: connect data lifecycle stages to business decision value.",
      },
      {
        title: "Activity walkthrough (1.1 to 1.7)",
        type: "text",
        order: 2,
        content:
          "# Activity Plan\n1. Activity 1.1 to 1.3: collection methods, web forms, RFID, and transaction flow.\n2. Activity 1.4: warehouse vs operational database reasoning.\n3. Activity 1.5 and 1.6: mining strategy and pattern extraction tasks.\n4. Activity 1.7: quality controls, metadata, rollback, and auditing.\n\nDocument each decision with a clear reason and expected outcome.",
      },
      {
        title: "Visual guide: data lifecycle pipeline",
        type: "diagram",
        order: 3,
        content:
          "Use this visual to track data from capture to warehouse, mining, and decision reporting.",
        diagramUrl: grade12Chapter1Diagram,
      },
      {
        title: "Activity sheet visual: Data lifecycle checklist",
        type: "diagram",
        order: 4,
        content:
          "Use this worksheet visual to verify each lifecycle stage from capture through governance controls.",
        diagramUrl: grade12Chapter1WorksheetDiagram,
      },
    ],
    assignmentTemplates: [
      {
        title: "Grade 12 Chapter 1 Practical Task - Data Lifecycle Design",
        description:
          "Step 1: Choose one dataset context (transport, retail, or school records).\nStep 2: Show two data-collection methods (for example web form and RFID).\nStep 3: Separate transactional storage from warehouse storage.\nStep 4: Define one mining question and expected pattern.\nStep 5: Add one data-quality check and one rollback/audit control.",
        priority: "high",
      },
      {
        title: "Grade 12 Chapter 1 Guided Worksheet - Warehouse vs Operations",
        description:
          "Step 1: Make a comparison table: operational database vs data warehouse.\nStep 2: Fill in purpose, data type, update frequency, and query style.\nStep 3: Write one business question suitable for warehouse analytics.\nStep 4: Explain why the same question is weak for live transaction DB.\nStep 5: Review table for precise terminology.",
        priority: "medium",
      },
      {
        title: "Grade 12 Chapter 1 Exam-Style Drill - Mining and Governance",
        description:
          "Step 1: Analyze a short case with a large historical dataset.\nStep 2: Propose a mining approach and expected insight.\nStep 3: List two metadata fields needed for interpretation.\nStep 4: Identify one data-quality risk and mitigation.\nStep 5: Conclude with a decision that management can take.",
        priority: "high",
      },
      {
        title: "Grade 12 Chapter 1 Memo Reflection - Data Management Fixes",
        description:
          "Step 1: Compare your lifecycle and mining answers against the memo.\nStep 2: Correct weak reasoning and missing controls.\nStep 3: Rewrite one answer in exam style (clear, concise, justified).\nStep 4: Note two quality checks you forgot and add them.\nStep 5: Submit corrected work with a short improvement plan.",
        priority: "medium",
      },
    ],
    quiz: {
      title: "Grade 12 Chapter 1 Database Management Quiz",
      description: "Applied questions from Chapter 1 database management activities.",
      difficulty: "hard",
      questions: [
        {
          questionText: "How does a data warehouse differ from an operational database?",
          type: "short_answer",
          correctAnswer: "A data warehouse integrates large historical datasets for analysis, while operational databases focus on current transactional processing.",
          explanation: "Both are relational systems but used for different workloads.",
        },
        {
          questionText: "Which technology is commonly used to automatically identify tagged items in logistics or ticketing?",
          type: "multiple_choice",
          options: ["RFID", "BIOS", "GPU", "SMTP"],
          correctAnswer: "RFID",
          explanation: "RFID is highlighted in capture and tracking scenarios.",
        },
        {
          questionText: "What is the main goal of data mining?",
          type: "short_answer",
          correctAnswer: "To identify useful patterns and trends in large datasets for decision support.",
          explanation: "Mining turns large data collections into actionable insight.",
        },
        {
          questionText: "Why is metadata important in data management?",
          type: "short_answer",
          correctAnswer: "Metadata describes data meaning, origin, and structure so data can be found, trusted, and integrated correctly.",
          explanation: "Without metadata, data interpretation and governance degrade.",
        },
        {
          questionText: "Design a simple lifecycle plan from collection to decision-making for a transport ticketing dataset.",
          type: "essay",
          correctAnswer: "Collect ticket scans and trip metadata, store transactions in an operational database, consolidate into a warehouse, mine usage patterns by route/time, and use results to optimize pricing and scheduling while enforcing data quality and rollback controls.",
          explanation: "This reflects Chapter 1's full data lifecycle model.",
        },
      ],
    },
  },
  {
    key: "it12-ch2-database-design-lab",
    title: "Grade 12 Chapter 2 Database Design Lab",
    description:
      "Chapter 2 database design drills: quality characteristics, anomalies, key structures, and normalization fixes.",
    grade: 12,
    order: 19,
    capsTags: ["grade12", "chapter2", "database-design", "activity-lab"],
    lessons: [
      {
        title: "Chapter 2 database design concept map",
        type: "text",
        order: 1,
        content:
          "# Chapter 2 Focus\n- Characteristics of high-quality databases\n- Insertion, deletion, and modification anomalies\n- Primary/foreign/alternative/composite keys\n- Normalization as a method to remove redundancy and anomalies\n\nGoal: transform weak table designs into robust relational structures.",
      },
      {
        title: "Activity walkthrough (2.1 to 2.3)",
        type: "text",
        order: 2,
        content:
          "# Activity Plan\n1. Activity 2.1: core terminology and quality attributes.\n2. Activity 2.2: anomaly detection in flawed table designs.\n3. Activity 2.3: normalization and key-structure redesign.\n\nShow your redesign steps explicitly: identify issue -> split tables -> define keys -> verify reduced redundancy.",
      },
      {
        title: "Visual guide: normalization before/after",
        type: "diagram",
        order: 3,
        content:
          "Use this visual to compare anomalous table designs against normalized relational layouts.",
        diagramUrl: grade12Chapter2Diagram,
      },
      {
        title: "Activity sheet visual: Normalization checklist",
        type: "diagram",
        order: 4,
        content:
          "Use this worksheet visual to move from anomaly detection to fully keyed normalized tables.",
        diagramUrl: grade12Chapter2WorksheetDiagram,
      },
    ],
    assignmentTemplates: [
      {
        title: "Grade 12 Chapter 2 Practical Task - Normalize a Broken Table",
        description:
          "Step 1: Start from one overloaded table with repeated fields.\nStep 2: Identify insertion, deletion, and update anomalies.\nStep 3: Split into logical entities and create separate tables.\nStep 4: Assign primary keys and define foreign key links.\nStep 5: Provide the final schema and explain why redundancy dropped.",
        priority: "high",
      },
      {
        title: "Grade 12 Chapter 2 Guided Worksheet - Keys and Integrity",
        description:
          "Step 1: Define primary, foreign, alternate, and composite keys.\nStep 2: For each sample table, choose the best key type.\nStep 3: Explain one integrity rule per table relationship.\nStep 4: Mark one bad key choice and explain why it fails.\nStep 5: Ensure all key names are consistent.",
        priority: "medium",
      },
      {
        title: "Grade 12 Chapter 2 Exam-Style Drill - Anomaly Diagnosis",
        description:
          "Step 1: Read a flawed design case.\nStep 2: Name each anomaly with direct evidence from the case.\nStep 3: Propose normalization steps in the correct order.\nStep 4: Show a before/after example row to prove improvement.\nStep 5: Conclude with one sentence on long-term maintainability.",
        priority: "high",
      },
      {
        title: "Grade 12 Chapter 2 Memo Reflection - Redesign Corrections",
        description:
          "Step 1: Compare your schema to the memo schema.\nStep 2: Correct missing keys, wrong links, or leftover redundancy.\nStep 3: Rewrite one weak explanation to include chapter terms.\nStep 4: Add one validation check you can run before submission.\nStep 5: Submit corrected schema and reflection notes.",
        priority: "medium",
      },
    ],
    quiz: {
      title: "Grade 12 Chapter 2 Database Design Quiz",
      description: "Database design and normalization checks based on chapter activities.",
      difficulty: "hard",
      questions: [
        {
          questionText: "Name three characteristics of a good database.",
          type: "short_answer",
          correctAnswer: "Accurate, consistent, and current.",
          explanation: "Completeness and relevance are also part of quality criteria.",
        },
        {
          questionText: "Which anomaly occurs when deleting one record unintentionally removes other needed information?",
          type: "multiple_choice",
          options: ["Deletion anomaly", "Insertion anomaly", "Caching anomaly", "Rendering anomaly"],
          correctAnswer: "Deletion anomaly",
          explanation: "Deletion anomalies remove required data as a side effect.",
        },
        {
          questionText: "What is normalization in database design?",
          type: "short_answer",
          correctAnswer: "A structured process of organizing tables to reduce redundancy and eliminate insertion, deletion, and update anomalies.",
          explanation: "Normalization improves integrity and maintainability.",
        },
        {
          questionText: "What does a foreign key do?",
          type: "short_answer",
          correctAnswer: "It links a field in one table to a primary or unique key in another table to represent relationships.",
          explanation: "Foreign keys enforce relational consistency between tables.",
        },
        {
          questionText: "Given one overloaded student table with repeated class details, describe how you would redesign it.",
          type: "essay",
          correctAnswer: "Split entities into separate tables (for example Students, Classes, Enrollments), assign primary keys per table, use foreign keys for relationships, and remove repeated fields so updates happen once per fact.",
          explanation: "This is the core Chapter 2 redesign pattern.",
        },
      ],
    },
  },
];
