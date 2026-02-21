import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Curriculum Seeding Script
 *
 * Seeds the CAPS (Curriculum and Assessment Policy Statement) curriculum
 * structure including grades, subjects, and topics for South African schools.
 */

// ============ CAPS CURRICULUM TOPICS ============

// Information Technology Grade 10 Topics (based on CAPS Section 3)
const IT_GRADE_10_TOPICS = [
  // Term 1
  {
    term: 1,
    title: "Basic Computing Concepts",
    subtopics: [
      "Computer systems (input, processing, output, storage)",
      "Hardware vs software",
      "Firmware and BIOS",
      "Data representation (binary, decimal, hexadecimal)",
      "Units of storage (bit, byte, KB, MB, GB, TB)",
      "ASCII and Unicode character encoding",
      "Digital divide and ergonomics",
      "Green computing and ethics",
    ],
    weighting: 15,
  },
  {
    term: 1,
    title: "Introduction to Algorithms",
    subtopics: [
      "Algorithm concepts and characteristics",
      "Pseudocode",
      "Flowcharts and flowchart symbols",
      "IPO charts (Input-Process-Output)",
      "Tracing algorithms with trace tables",
    ],
    weighting: 10,
  },
  {
    term: 1,
    title: "Introduction to Delphi and Solution Development",
    subtopics: [
      "The Delphi IDE (form designer, code editor, object inspector)",
      "GUI components (TButton, TEdit, TLabel, TMemo, TRadioGroup, TComboBox)",
      "Event-driven programming (OnClick handlers)",
      "Variables and data types (Integer, Real, String, Char, Boolean)",
      "Constants",
      "Type conversion (StrToInt, IntToStr, StrToFloat, FloatToStr)",
      "Arithmetic operators (+, -, *, /, div, mod)",
      "Basic input and output",
    ],
    weighting: 20,
  },
  // Term 2
  {
    term: 2,
    title: "Hardware Components",
    subtopics: [
      "Input devices (keyboard, mouse, scanner, microphone, webcam)",
      "Output devices (monitor, printer, speakers, projector)",
      "Storage types (RAM, ROM, HDD, SSD, optical, cloud)",
      "The system unit (motherboard, CPU, RAM, PSU, GPU)",
      "Ports and connections (USB, HDMI, Ethernet, audio)",
    ],
    weighting: 10,
  },
  {
    term: 2,
    title: "System Software and Networks",
    subtopics: [
      "Operating system functions (process, memory, file, device management)",
      "Utility software (antivirus, defragmenter, backup, compression)",
      "Device drivers",
      "Network types (LAN, WAN, PAN, MAN)",
      "Network components (router, switch, modem, NIC)",
      "Network topologies (star, bus, ring, mesh)",
      "Electronic communications (email protocols, IM, VoIP)",
    ],
    weighting: 10,
  },
  {
    term: 2,
    title: "Selection and Boolean Logic",
    subtopics: [
      "IF and IF-ELSE statements",
      "Nested IF statements",
      "Comparison operators (=, <>, >, <, >=, <=)",
      "Boolean operators (AND, OR, NOT)",
      "Truth tables",
      "CASE statements",
      "GUI selection (TRadioGroup, TComboBox, TCheckBox)",
    ],
    weighting: 10,
  },
  {
    term: 2,
    title: "Introduction to Strings",
    subtopics: [
      "String basics (1-based indexing, concatenation)",
      "String functions (Length, Copy, Pos, UpperCase, LowerCase, Trim)",
      "Character access (s[i])",
      "Insert and Delete procedures",
      "Counting characters and reversing strings",
    ],
    weighting: 10,
  },
  // Term 3
  {
    term: 3,
    title: "Computer Management and Security",
    subtopics: [
      "File and folder management",
      "File properties and housekeeping",
      "Malware types (virus, worm, Trojan, spyware, ransomware, adware)",
      "Protection methods (antivirus, firewall, strong passwords, updates, backups)",
      "POPIA (Protection of Personal Information Act)",
    ],
    weighting: 8,
  },
  {
    term: 3,
    title: "Internet and the World Wide Web",
    subtopics: [
      "Internet vs WWW",
      "How the internet works (DNS, IP addresses)",
      "Key protocols (HTTP/HTTPS, FTP, SMTP, POP3/IMAP, TCP/IP)",
      "Internet connections (ADSL, fibre, mobile data, satellite)",
      "Web browsers and URLs",
      "Search techniques (quotes, minus, site:, filetype:)",
      "Evaluating online sources",
    ],
    weighting: 8,
  },
  {
    term: 3,
    title: "Loops and Patterns",
    subtopics: [
      "FOR loops (counting up and down)",
      "WHILE loops",
      "REPEAT-UNTIL loops",
      "Counters and accumulators",
      "Nested loops for pattern building",
      "Avoiding infinite loops",
    ],
    weighting: 15,
  },
  // Term 4
  {
    term: 4,
    title: "Internet Services and Online Applications",
    subtopics: [
      "Cloud computing (SaaS, PaaS, IaaS)",
      "Cloud storage advantages and disadvantages",
      "Web applications",
      "E-commerce (B2C, B2B, C2C)",
      "Online safety (HTTPS, 2FA, strong passwords)",
      "Online collaboration tools",
    ],
    weighting: 7,
  },
  {
    term: 4,
    title: "Text Files and File Handling",
    subtopics: [
      "TextFile type and AssignFile",
      "Reading files (Reset, Readln, EOF, CloseFile)",
      "Writing files (Rewrite, Writeln)",
      "Appending to files (Append)",
      "FileExists check",
      "Processing file data (totals and averages)",
    ],
    weighting: 12,
  },
];

// Information Technology Grade 11 Topics (based on CAPS Section 3)
const IT_GRADE_11_TOPICS = [
  // Term 1
  {
    term: 1,
    title: "Advanced Hardware Concepts",
    subtopics: [
      "Motherboard components (CPU socket, RAM slots, chipset, CMOS battery)",
      "CPU architecture (Fetch-Decode-Execute cycle)",
      "CPU performance factors (clock speed, cores, cache, word size, bus speed)",
      "Memory hierarchy (registers, cache, RAM, secondary storage)",
      "RAM types (SRAM, DRAM, DDR4/DDR5)",
      "ROM vs RAM",
      "Virtual memory",
      "Performance improvement strategies",
    ],
    weighting: 10,
  },
  {
    term: 1,
    title: "Software and Network Security",
    subtopics: [
      "Software categories (system, application)",
      "Software licensing (proprietary, open source, freeware, shareware, Creative Commons)",
      "EULA and software piracy",
      "Network threats (MITM, DoS, packet sniffing, SQL injection, brute force, social engineering)",
      "Encryption (symmetric vs asymmetric)",
      "SSL/TLS and VPN",
      "Authentication methods (passwords, biometrics, tokens, MFA)",
    ],
    weighting: 10,
  },
  {
    term: 1,
    title: "Arrays, Searching, and Sorting",
    subtopics: [
      "One-dimensional array declaration and access",
      "Array operations (total, average, maximum, count)",
      "Linear search with flag",
      "Binary search (sorted array requirement)",
      "Bubble sort algorithm",
      "Selection sort algorithm",
      "Algorithm complexity (O(n), O(log n), O(n^2))",
    ],
    weighting: 15,
  },
  {
    term: 1,
    title: "Strings, Dates, and Type Conversion",
    subtopics: [
      "Advanced string functions (StringReplace, Trim, LastDelimiter)",
      "Extracting words from strings",
      "Counting specific characters",
      "Palindrome checking",
      "Date functions (Now, Date, EncodeDate, DaysBetween)",
      "FormatDateTime and format codes",
      "Calculating age from dates",
    ],
    weighting: 10,
  },
  // Term 2
  {
    term: 2,
    title: "User-Defined Methods",
    subtopics: [
      "Procedures (no return value)",
      "Functions (return a value via Result)",
      "Value parameters vs reference parameters (var)",
      "Scope (local vs global variables)",
      "Input validation with functions",
      "Code reusability and maintainability",
    ],
    weighting: 15,
  },
  {
    term: 2,
    title: "Database Fundamentals",
    subtopics: [
      "Relational database concepts (tables, fields, records)",
      "Primary keys and foreign keys",
      "Relationships (one-to-one, one-to-many, many-to-many)",
      "SQL SELECT with WHERE and ORDER BY",
      "Aggregate functions (COUNT, SUM, AVG, MAX, MIN)",
      "DISTINCT and LIKE wildcards",
      "ADO components in Delphi (TADOConnection, TADOQuery, TDBGrid, TDataSource)",
      "Running SQL queries from Delphi",
    ],
    weighting: 15,
  },
  {
    term: 2,
    title: "Advanced Text File Processing",
    subtopics: [
      "Structured text files with delimiters",
      "Parsing delimited lines (Pos, Copy, Delete)",
      "Reading files into arrays",
      "Writing processed data to new files",
      "Reset vs Rewrite vs Append",
      "Error handling with try...finally",
    ],
    weighting: 10,
  },
  // Term 3
  {
    term: 3,
    title: "Database Design Concepts",
    subtopics: [
      "Entity-Relationship Diagrams (ERDs)",
      "ERD components (entities, attributes, relationships)",
      "Resolving many-to-many with junction tables",
      "Normalisation (1NF, 2NF, 3NF)",
      "Data integrity (entity, referential, domain)",
    ],
    weighting: 10,
  },
  {
    term: 3,
    title: "Database Programming in Delphi",
    subtopics: [
      "SQL INSERT statements",
      "SQL UPDATE statements",
      "SQL DELETE statements",
      "GROUP BY and HAVING clauses",
      "Open vs ExecSQL in Delphi",
      "Parameterised queries (preventing SQL injection)",
    ],
    weighting: 15,
  },
  {
    term: 3,
    title: "Social Implications of Technology",
    subtopics: [
      "Cybercrime types (hacking, identity theft, phishing, cyberbullying)",
      "Digital citizenship",
      "POPIA (Protection of Personal Information Act)",
      "ECT Act (Electronic Communications and Transactions Act)",
      "Copyright Act and intellectual property",
      "Creative Commons licensing",
      "Impact of technology on society (positive and negative)",
    ],
    weighting: 8,
  },
  // Term 4
  {
    term: 4,
    title: "Emerging Technologies",
    subtopics: [
      "Internet of Things (IoT) concepts and examples",
      "IoT concerns (security, privacy, compatibility)",
      "Big data and the 5 V's (volume, velocity, variety, veracity, value)",
      "Artificial Intelligence (machine learning, NLP, computer vision)",
      "Cloud computing trends (edge, serverless, hybrid)",
      "Modern internet services (streaming, social media, online learning)",
      "Impact on employment and digital literacy",
    ],
    weighting: 7,
  },
  {
    term: 4,
    title: "Consolidation and PAT Preparation",
    subtopics: [
      "Integrated programming (combining files, arrays, strings, databases, methods)",
      "PAT Phase 1: Analysis and design (IPO charts, ERD, UI mockups)",
      "PAT Phase 2: Coding and database implementation",
      "PAT Phase 3: Testing and documentation",
      "Input validation and error handling patterns",
      "Common exam patterns and integration exercises",
    ],
    weighting: 10,
  },
];

// Information Technology Grade 12 Topics (based on CAPS Section 3)
const IT_GRADE_12_TOPICS = [
  // Term 1
  {
    term: 1,
    title: "Algorithms and IPO",
    subtopics: [
      "Algorithm design and step-by-step logic",
      "IPO tables for planning",
      "Flowcharts and pseudocode",
      "Tracing loops and logic steps",
    ],
    weighting: 5,
  },
  {
    term: 1,
    title: "Selection and Boolean Logic",
    subtopics: [
      "IF, IF-ELSE, and CASE statements review",
      "Boolean logic with AND and OR",
      "GUI-driven selection (RadioGroup, ComboBox)",
    ],
    weighting: 5,
  },
  {
    term: 1,
    title: "Loops and Pattern Building",
    subtopics: [
      "For and while loops",
      "Nested loops for patterns",
      "Accumulators and running totals",
    ],
    weighting: 5,
  },
  {
    term: 1,
    title: "Strings and ASCII Manipulation",
    subtopics: [
      "String indexing and helper functions (Length, Copy, Pos, Insert, Delete, UpCase)",
      "Reverse strings and remove vowels",
      "ASCII checks and sums (Ord, Chr)",
    ],
    weighting: 8,
  },
  {
    term: 1,
    title: "Text Files and File Handling",
    subtopics: [
      "AssignFile, Reset, Readln, EOF, CloseFile",
      "FileExists check",
      "Calculating averages from file data (FormatFloat)",
    ],
    weighting: 7,
  },
  {
    term: 1,
    title: "Arrays, Search, and Sorting",
    subtopics: [
      "1D arrays and averages",
      "Linear search with flag",
      "Bubble sort with swaps",
      "Unique random number generation",
    ],
    weighting: 10,
  },
  {
    term: 1,
    title: "Two-Dimensional Arrays",
    subtopics: [
      "Declaring and populating 2D arrays",
      "Row and column totals",
      "Finding maximum in a 2D array",
      "Loading 2D arrays from text files",
    ],
    weighting: 8,
  },
  // Term 2
  {
    term: 2,
    title: "Databases and SQL",
    subtopics: [
      "Tables, fields, and primary keys",
      "SQL SELECT with WHERE and ORDER BY",
      "GROUP BY and COUNT",
      "TADOQuery and dataset loops (First, EOF, Edit/Post, Next)",
    ],
    weighting: 10,
  },
  {
    term: 2,
    title: "Advanced SQL and Database Manipulation",
    subtopics: [
      "SQL JOINs (INNER JOIN, LEFT JOIN)",
      "Subqueries",
      "SQL INSERT, UPDATE, DELETE",
      "Data warehousing concepts",
      "Data mining techniques (classification, clustering, association, prediction)",
      "Database normalisation review (1NF, 2NF, 3NF)",
    ],
    weighting: 12,
  },
  {
    term: 2,
    title: "OOP Fundamentals",
    subtopics: [
      "Classes, attributes, and constructors",
      "Methods and toString",
      "Online status example (Boolean-based functions)",
    ],
    weighting: 8,
  },
  {
    term: 2,
    title: "Advanced OOP: Inheritance and Polymorphism",
    subtopics: [
      "Inheritance (base class, derived class, IS-A relationship)",
      "Constructor chaining (inherited keyword)",
      "Polymorphism (virtual, override)",
      "Abstract classes and abstract methods",
    ],
    weighting: 12,
  },
  // Term 3
  {
    term: 3,
    title: "Systems, Communication, and Social Impact",
    subtopics: [
      "Systems technologies (hardware, software, firmware)",
      "Communication and internet technologies (IP, IMAP)",
      "Data and information concepts",
      "ERD concepts and GUID/UUID",
      "Software licensing and the digital divide",
      "Creative Commons",
    ],
    weighting: 8,
  },
  {
    term: 3,
    title: "Computer Management and Emerging Technologies",
    subtopics: [
      "Troubleshooting methodology (6 steps)",
      "Performance monitoring and backup strategies",
      "Cloud computing (public, private, hybrid, multi-cloud)",
      "Artificial Intelligence (narrow AI, general AI, deep learning)",
      "Virtual Reality, Augmented Reality, and Mixed Reality",
      "Impact on business and society",
    ],
    weighting: 8,
  },
  {
    term: 3,
    title: "Internet Services, Networks, and Security",
    subtopics: [
      "SEO techniques",
      "Online applications and e-government services",
      "SSL/TLS, digital certificates, HTTPS",
      "Two-factor authentication and biometrics",
      "Social networking implications and digital footprint",
      "Cybercrime (ransomware, spear phishing, cryptojacking)",
      "Cybercrimes Act (2020)",
    ],
    weighting: 8,
  },
];

// Mathematics Grade 10 Topics (based on CAPS)
const MATH_GRADE_10_TOPICS = [
  {
    term: 1,
    title: "Algebraic Expressions",
    subtopics: [
      "Number patterns",
      "Simplification of algebraic expressions",
      "Factorization",
      "Products of algebraic expressions",
    ],
    weighting: 15,
  },
  {
    term: 1,
    title: "Equations and Inequalities",
    subtopics: [
      "Linear equations",
      "Quadratic equations",
      "Literal equations",
      "Linear inequalities",
    ],
    weighting: 15,
  },
  {
    term: 1,
    title: "Exponents",
    subtopics: [
      "Laws of exponents",
      "Simplification using laws of exponents",
      "Rational exponents",
    ],
    weighting: 10,
  },
  {
    term: 2,
    title: "Number Patterns",
    subtopics: ["Linear patterns", "Quadratic patterns", "General terms"],
    weighting: 10,
  },
  {
    term: 2,
    title: "Functions",
    subtopics: [
      "Definition and notation",
      "Linear functions",
      "Quadratic functions",
      "Hyperbolic functions",
      "Exponential functions",
    ],
    weighting: 20,
  },
  {
    term: 3,
    title: "Analytical Geometry",
    subtopics: [
      "Distance formula",
      "Midpoint formula",
      "Gradient of a line",
      "Equation of a straight line",
    ],
    weighting: 10,
  },
  {
    term: 3,
    title: "Trigonometry",
    subtopics: [
      "Trigonometric ratios",
      "Solving right-angled triangles",
      "Trigonometric graphs",
      "Reduction formulae",
    ],
    weighting: 15,
  },
  {
    term: 4,
    title: "Euclidean Geometry",
    subtopics: [
      "Properties of triangles",
      "Congruence",
      "Similarity",
      "Theorem of Pythagoras",
    ],
    weighting: 12,
  },
  {
    term: 4,
    title: "Measurement",
    subtopics: ["Surface area", "Volume", "Conversion of units"],
    weighting: 8,
  },
  {
    term: 4,
    title: "Statistics and Probability",
    subtopics: [
      "Data collection",
      "Measures of central tendency",
      "Measures of dispersion",
      "Probability",
    ],
    weighting: 10,
  },
];

// Mathematics Grade 11 Topics (based on CAPS)
const MATH_GRADE_11_TOPICS = [
  {
    term: 1,
    title: "Exponents and Surds",
    subtopics: [
      "Rational exponents and laws of exponents",
      "Simplification of surd expressions",
      "Equations involving surds",
      "Exponential equations using substitution",
    ],
    weighting: 10,
  },
  {
    term: 1,
    title: "Equations and Inequalities",
    subtopics: [
      "Quadratic equations (factorisation and quadratic formula)",
      "Simultaneous equations (one linear, one quadratic)",
      "Completing the square",
      "Nature of roots and the discriminant",
      "Quadratic inequalities",
    ],
    weighting: 15,
  },
  {
    term: 1,
    title: "Number Patterns",
    subtopics: [
      "Quadratic sequences",
      "First and second differences",
      "General term of a quadratic sequence (T_n = an² + bn + c)",
    ],
    weighting: 10,
  },
  {
    term: 2,
    title: "Functions and Graphs",
    subtopics: [
      "Parabola: y = a(x - p)² + q",
      "Hyperbola: y = a/(x - p) + q",
      "Exponential function: y = a·b^(x-p) + q",
      "Domain, range, and asymptotes",
      "Transformations (shift, reflect, stretch)",
      "Average gradient between two points",
    ],
    weighting: 20,
  },
  {
    term: 2,
    title: "Trigonometry",
    subtopics: [
      "Trigonometric identities (quotient and squared)",
      "Reduction formulae and negative angles",
      "Co-function relationships",
      "General solutions of trigonometric equations",
      "Trigonometric graphs: amplitude, period, phase shift",
    ],
    weighting: 15,
  },
  {
    term: 3,
    title: "Analytical Geometry",
    subtopics: [
      "Inclination of a line",
      "Angle between two lines",
      "Equations of parallel and perpendicular lines",
      "Properties of quadrilaterals using coordinates",
    ],
    weighting: 10,
  },
  {
    term: 3,
    title: "Euclidean Geometry",
    subtopics: [
      "Circle theorems (central angle, inscribed angle)",
      "Angles in the same segment",
      "Angle in a semicircle",
      "Cyclic quadrilateral (opposite angles supplementary)",
      "Tangent theorems (tangent-radius, two tangents from external point)",
      "Tangent-chord angle",
    ],
    weighting: 12,
  },
  {
    term: 4,
    title: "Statistics",
    subtopics: [
      "Measures of central tendency and dispersion",
      "Standard deviation and variance",
      "Five-number summary and box-and-whisker plots",
      "Cumulative frequency and ogives",
      "Symmetric and skewed distributions",
    ],
    weighting: 10,
  },
  {
    term: 4,
    title: "Probability",
    subtopics: [
      "Addition rule and Venn diagrams",
      "Independent and dependent events",
      "Tree diagrams",
      "Contingency tables",
      "Complementary events",
    ],
    weighting: 10,
  },
  {
    term: 4,
    title: "Finance, Growth and Decay",
    subtopics: [
      "Simple and compound interest",
      "Straight-line and reducing-balance depreciation",
      "Nominal and effective interest rates",
      "Timelines for financial problems",
    ],
    weighting: 10,
  },
];

// Mathematics Grade 12 Topics (based on CAPS)
const MATH_GRADE_12_TOPICS = [
  {
    term: 1,
    title: "Sequences and Series",
    subtopics: [
      "Arithmetic sequences and series",
      "Geometric sequences and series",
      "Sigma notation",
      "Convergent geometric series (sum to infinity)",
    ],
    weighting: 15,
  },
  {
    term: 1,
    title: "Functions: Inverses",
    subtopics: [
      "Inverse functions (reflection in y = x)",
      "Inverse of linear, quadratic, and exponential functions",
      "Logarithmic function as inverse of exponential",
      "Logarithm laws",
      "Domain restrictions for invertibility",
    ],
    weighting: 10,
  },
  {
    term: 1,
    title: "Financial Mathematics",
    subtopics: [
      "Future value annuity",
      "Present value annuity",
      "Sinking funds",
      "Loan repayments and balance outstanding",
      "Deferred payments",
    ],
    weighting: 10,
  },
  {
    term: 2,
    title: "Trigonometry: Compound and Double Angles",
    subtopics: [
      "Compound angle formulae (cos(A±B), sin(A±B))",
      "Double angle formulae (sin2A, cos2A)",
      "Solving trig equations using compound/double angles",
      "Sine rule, cosine rule, area rule",
      "2D and 3D trigonometric problems",
    ],
    weighting: 15,
  },
  {
    term: 2,
    title: "Polynomials",
    subtopics: [
      "Remainder theorem",
      "Factor theorem",
      "Solving cubic equations by factorisation",
    ],
    weighting: 8,
  },
  {
    term: 3,
    title: "Differential Calculus",
    subtopics: [
      "Limits and average gradient",
      "Differentiation from first principles",
      "Differentiation rules (power, constant, sum/difference)",
      "Equation of a tangent line",
      "Cubic graphs (turning points, points of inflection)",
      "Optimisation problems (maxima and minima)",
    ],
    weighting: 18,
  },
  {
    term: 3,
    title: "Analytical Geometry: Circles",
    subtopics: [
      "Equation of a circle (standard and general form)",
      "Completing the square",
      "Tangent to a circle",
      "Intersection of a line and a circle",
    ],
    weighting: 10,
  },
  {
    term: 3,
    title: "Euclidean Geometry: Proportionality and Similarity",
    subtopics: [
      "Proportionality theorem (line parallel to one side)",
      "Mid-point theorem",
      "Similar triangles (conditions and properties)",
      "Proof of the Pythagorean theorem using similarity",
    ],
    weighting: 10,
  },
  {
    term: 4,
    title: "Statistics: Regression and Correlation",
    subtopics: [
      "Scatter plots and types of correlation",
      "Correlation coefficient (r)",
      "Least squares regression line (y = a + bx)",
      "Interpolation and extrapolation",
    ],
    weighting: 8,
  },
  {
    term: 4,
    title: "Counting Principles and Probability",
    subtopics: [
      "Fundamental counting principle",
      "Factorial notation",
      "Permutations (with and without repetition)",
      "Probability using counting techniques",
    ],
    weighting: 8,
  },
];

// ============ SEEDING FUNCTIONS ============

async function ensureCurriculum(): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM curricula WHERE name = 'CAPS' AND country = 'South Africa'
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO curricula (name, country, description, is_active)
    VALUES (
      'CAPS',
      'South Africa',
      'Curriculum and Assessment Policy Statement - The national curriculum framework for South African schools',
      true
    )
    RETURNING id
  `);

  return inserted.rows[0].id;
}

async function ensureGrade(
  curriculumId: number,
  level: number
): Promise<number> {
  const label = `Grade ${level}`;

  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM grades WHERE curriculum_id = ${curriculumId} AND level = ${level}
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO grades (curriculum_id, level, label)
    VALUES (${curriculumId}, ${level}, ${label})
    RETURNING id
  `);

  return inserted.rows[0].id;
}

async function ensureSubject(name: string): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM subjects WHERE name = ${name}
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  const code = name
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .substring(0, 3);

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO subjects (name, code, description, is_active)
    VALUES (${name}, ${code}, ${`${name} - CAPS Subject`}, true)
    RETURNING id
  `);

  return inserted.rows[0].id;
}

async function ensureTopic(
  subjectId: number,
  gradeId: number,
  parentTopicId: number | null,
  title: string,
  term: number | null,
  order: number,
  weighting: number | null,
  capsReference: string | null
): Promise<number> {
  // Check if topic already exists
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM topics
    WHERE subject_id = ${subjectId}
      AND grade_id = ${gradeId}
      AND title = ${title}
      AND (parent_topic_id IS NOT DISTINCT FROM ${parentTopicId})
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO topics (subject_id, grade_id, parent_topic_id, title, term_number, "order", weighting, caps_reference)
    VALUES (${subjectId}, ${gradeId}, ${parentTopicId}, ${title}, ${term}, ${order}, ${weighting}, ${capsReference})
    RETURNING id
  `);

  return inserted.rows[0].id;
}

async function ensureLearningOutcome(
  topicId: number,
  code: string,
  description: string,
  bloomsLevel: string
): Promise<void> {
  // Check if outcome already exists
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM learning_outcomes
    WHERE topic_id = ${topicId} AND description = ${description}
  `);

  if (existing.rows[0]) {
    return;
  }

  await db.execute(sql`
    INSERT INTO learning_outcomes (topic_id, code, description, blooms_level)
    VALUES (${topicId}, ${code}, ${description}, ${bloomsLevel})
  `);
}

// ============ MAIN SEEDING ============

async function seedCurriculum() {
  console.log("Starting CAPS Curriculum seeding...\n");

  // Create curriculum
  const curriculumId = await ensureCurriculum();
  console.log(`CAPS Curriculum ID: ${curriculumId}`);

  // Create grades 10-12 (matric grades)
  const grades = new Map<number, number>();
  for (const level of [10, 11, 12]) {
    const gradeId = await ensureGrade(curriculumId, level);
    grades.set(level, gradeId);
    console.log(`Grade ${level} ID: ${gradeId}`);
  }

  // ============ HELPER: Seed topics for a subject+grade ============
  async function seedSubjectGradeTopics(
    subjectId: number,
    gradeId: number,
    topics: typeof IT_GRADE_10_TOPICS,
    codePrefix: string,
    label: string
  ) {
    console.log(`\n=== Seeding ${label} Topics ===`);

    let topicOrder = 0;
    for (const topic of topics) {
      topicOrder++;

      const mainTopicId = await ensureTopic(
        subjectId,
        gradeId,
        null,
        topic.title,
        topic.term,
        topicOrder,
        topic.weighting,
        `CAPS ${label} Term${topic.term}`
      );

      console.log(`  + Topic: ${topic.title} (Term ${topic.term})`);

      let subtopicOrder = 0;
      for (const subtopic of topic.subtopics) {
        subtopicOrder++;

        const subtopicId = await ensureTopic(
          subjectId,
          gradeId,
          mainTopicId,
          subtopic,
          topic.term,
          subtopicOrder,
          null,
          null
        );

        await ensureLearningOutcome(
          subtopicId,
          `${codePrefix}.${topicOrder}.${subtopicOrder}`,
          `Learner can demonstrate understanding and application of ${subtopic.toLowerCase()}`,
          "Apply"
        );
      }
    }
  }

  // ============ INFORMATION TECHNOLOGY ============
  const itSubjectId = await ensureSubject("Information Technology");
  const grade10Id = grades.get(10)!;
  const grade11Id = grades.get(11)!;
  const grade12Id = grades.get(12)!;

  await seedSubjectGradeTopics(itSubjectId, grade10Id, IT_GRADE_10_TOPICS, "IT10", "IT Gr10");
  await seedSubjectGradeTopics(itSubjectId, grade11Id, IT_GRADE_11_TOPICS, "IT11", "IT Gr11");
  await seedSubjectGradeTopics(itSubjectId, grade12Id, IT_GRADE_12_TOPICS, "IT12", "IT Gr12");

  // ============ MATHEMATICS ============
  const mathSubjectId = await ensureSubject("Mathematics");

  await seedSubjectGradeTopics(mathSubjectId, grade10Id, MATH_GRADE_10_TOPICS, "MA10", "Math Gr10");
  await seedSubjectGradeTopics(mathSubjectId, grade11Id, MATH_GRADE_11_TOPICS, "MA11", "Math Gr11");
  await seedSubjectGradeTopics(mathSubjectId, grade12Id, MATH_GRADE_12_TOPICS, "MA12", "Math Gr12");

  // ============ SUMMARY ============
  console.log("\n=== Seeding Summary ===");

  const topicCount = await db.execute<{ count: number }>(sql`
    SELECT COUNT(*)::int as count FROM topics
  `);

  const outcomeCount = await db.execute<{ count: number }>(sql`
    SELECT COUNT(*)::int as count FROM learning_outcomes
  `);

  console.log(`Total topics created: ${topicCount.rows[0]?.count ?? 0}`);
  console.log(
    `Total learning outcomes created: ${outcomeCount.rows[0]?.count ?? 0}`
  );
  console.log("\nCurriculum seeding complete!");
}

// ============ RUN ============

seedCurriculum().catch((error) => {
  console.error("Seeding failed:", error);
  process.exit(1);
});
