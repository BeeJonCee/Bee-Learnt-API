import type { ModuleSeed } from "../types.js";

export const grade11Modules: ModuleSeed[] = [
  // ──────────────────────────────────────────
  // TERM 1
  // ──────────────────────────────────────────

  {
    key: "math11-exponents-surds",
    title: "Exponents and Surds",
    description:
      "Rational exponents, simplification of surd expressions, and equations involving surds.",
    grade: 11,
    order: 1,
    capsTags: [
      "exponents",
      "surds",
      "rational exponents",
      "simplification",
    ],
    lessons: [
      {
        title: "Rational Exponents and Laws of Exponents",
        type: "text",
        order: 1,
        content: `# Rational Exponents

## Recap of Exponent Laws

- a^m x a^n = a^(m+n)
- a^m / a^n = a^(m-n)
- (a^m)^n = a^(mn)
- (ab)^n = a^n . b^n
- a^0 = 1  (a ≠ 0)
- a^(-n) = 1/a^n

## Rational Exponents

a^(1/n) = the nth root of a

**Examples:**
- 8^(1/3) = cube root of 8 = 2
- 27^(2/3) = (27^(1/3))^2 = 3^2 = 9
- x^(3/4) means the 4th root of x^3

## Simplification

Always convert surds to rational exponents before applying laws.

**Example:** Simplify (16x^8)^(3/4)
= 16^(3/4) . x^(8 x 3/4)
= (2^4)^(3/4) . x^6
= 2^3 . x^6
= 8x^6`,
      },
      {
        title: "Surds: Simplification and Operations",
        type: "text",
        order: 2,
        content: `# Surds

A surd is an irrational root that cannot be simplified to a rational number.

## Simplifying Surds

sqrt(a x b) = sqrt(a) x sqrt(b)

**Example:** sqrt(48) = sqrt(16 x 3) = 4.sqrt(3)

## Adding and Subtracting Surds

Only like surds can be combined.

**Example:** 3.sqrt(5) + 2.sqrt(5) = 5.sqrt(5)
But sqrt(2) + sqrt(3) cannot be simplified further.

## Multiplying Surds

sqrt(a) x sqrt(b) = sqrt(ab)

**Example:** sqrt(3) x sqrt(12) = sqrt(36) = 6

## Rationalising the Denominator

Multiply numerator and denominator by the conjugate surd.

**Example:** 5 / (sqrt(3) - 1)
= 5(sqrt(3) + 1) / ((sqrt(3) - 1)(sqrt(3) + 1))
= 5(sqrt(3) + 1) / (3 - 1)
= 5(sqrt(3) + 1) / 2`,
      },
      {
        title: "Equations Involving Surds and Exponents",
        type: "text",
        order: 3,
        content: `# Equations with Surds and Exponents

## Exponential Equations

Strategy: Express both sides with the same base, then equate exponents.

**Example:** 2^(x+1) = 16
2^(x+1) = 2^4
x + 1 = 4
x = 3

## Surd Equations

Strategy: Isolate the surd, then square both sides. Always check for extraneous solutions.

**Example:** sqrt(2x + 3) = 5
2x + 3 = 25
2x = 22
x = 11
Check: sqrt(25) = 5 ✓

## Equations Requiring Substitution

**Example:** 4^x - 6(2^x) + 8 = 0
Let k = 2^x:
k^2 - 6k + 8 = 0
(k - 2)(k - 4) = 0
k = 2 or k = 4
2^x = 2 → x = 1
2^x = 4 → x = 2`,
      },
    ],
    quiz: {
      title: "Exponents and Surds Quiz",
      description: "Test your understanding of rational exponents, surds, and exponential equations.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Simplify: 27^(2/3)",
          type: "multiple_choice",
          options: ["3", "9", "18", "6"],
          correctAnswer: "9",
          explanation: "27^(1/3) = 3, then 3^2 = 9.",
        },
        {
          questionText: "Simplify: sqrt(72)",
          type: "multiple_choice",
          options: ["6.sqrt(2)", "4.sqrt(3)", "3.sqrt(8)", "2.sqrt(18)"],
          correctAnswer: "6.sqrt(2)",
          explanation: "sqrt(72) = sqrt(36 x 2) = 6.sqrt(2).",
        },
        {
          questionText: "Solve: 3^(2x) = 81",
          type: "short_answer",
          correctAnswer: "x = 2",
          explanation: "81 = 3^4, so 2x = 4, x = 2.",
        },
        {
          questionText: "Rationalise: 4 / sqrt(2)",
          type: "short_answer",
          correctAnswer: "2.sqrt(2)",
          explanation: "4 / sqrt(2) = 4.sqrt(2) / 2 = 2.sqrt(2).",
        },
        {
          questionText: "Simplify: (8x^6)^(2/3)",
          type: "multiple_choice",
          options: ["4x^4", "2x^4", "4x^3", "8x^4"],
          correctAnswer: "4x^4",
          explanation: "8^(2/3) = (2^3)^(2/3) = 4, x^(6 x 2/3) = x^4.",
        },
      ],
    },
  },

  {
    key: "math11-equations-inequalities",
    title: "Equations and Inequalities",
    description:
      "Quadratic equations, simultaneous equations, quadratic inequalities, and the nature of roots.",
    grade: 11,
    order: 2,
    capsTags: [
      "quadratic equations",
      "simultaneous equations",
      "inequalities",
      "nature of roots",
      "discriminant",
    ],
    lessons: [
      {
        title: "Quadratic Equations and the Quadratic Formula",
        type: "text",
        order: 1,
        content: `# Quadratic Equations

A quadratic equation has the form ax^2 + bx + c = 0.

## Methods of Solving

### 1. Factorisation
Factor the quadratic and set each factor to zero.

**Example:** x^2 - 5x + 6 = 0
(x - 2)(x - 3) = 0
x = 2 or x = 3

### 2. Quadratic Formula
x = (-b ± sqrt(b^2 - 4ac)) / (2a)

**Example:** 2x^2 + 3x - 2 = 0
a = 2, b = 3, c = -2
x = (-3 ± sqrt(9 + 16)) / 4
x = (-3 ± 5) / 4
x = 1/2 or x = -2

### 3. Completing the Square
Rewrite ax^2 + bx + c = 0 in the form a(x - p)^2 + q = 0.`,
      },
      {
        title: "Simultaneous Equations",
        type: "text",
        order: 2,
        content: `# Simultaneous Equations (one linear, one quadratic)

## Strategy
1. From the linear equation, express one variable in terms of the other.
2. Substitute into the quadratic equation.
3. Solve the resulting quadratic.
4. Back-substitute to find the other variable.

**Example:**
y = x + 1  ... (1)
x^2 + y^2 = 13  ... (2)

Substitute (1) into (2):
x^2 + (x + 1)^2 = 13
x^2 + x^2 + 2x + 1 = 13
2x^2 + 2x - 12 = 0
x^2 + x - 6 = 0
(x + 3)(x - 2) = 0
x = -3 or x = 2

If x = -3: y = -2
If x = 2: y = 3`,
      },
      {
        title: "Nature of Roots and Quadratic Inequalities",
        type: "text",
        order: 3,
        content: `# Nature of Roots

The discriminant delta = b^2 - 4ac determines the nature of roots:

| Discriminant | Nature of Roots |
|---|---|
| delta > 0, perfect square | Two distinct rational roots |
| delta > 0, not perfect square | Two distinct irrational roots |
| delta = 0 | Two equal (repeated) real roots |
| delta < 0 | No real roots (non-real/complex) |

**Example:** For 2x^2 - 4x + 5 = 0
delta = 16 - 40 = -24 < 0 → no real roots

# Quadratic Inequalities

## Method
1. Solve the corresponding equation ax^2 + bx + c = 0 to find critical values.
2. Draw a number line and test intervals.
3. Use a parabola sketch to determine the sign in each interval.

**Example:** x^2 - 5x + 6 < 0
(x - 2)(x - 3) < 0
Critical values: x = 2 and x = 3
The parabola opens upward, so it is negative between the roots:
2 < x < 3`,
      },
    ],
    quiz: {
      title: "Equations and Inequalities Quiz",
      description: "Quadratic equations, simultaneous equations, nature of roots, and inequalities.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Solve: x^2 - 7x + 12 = 0",
          type: "multiple_choice",
          options: ["x = 3 or x = 4", "x = -3 or x = -4", "x = 2 or x = 6", "x = 1 or x = 12"],
          correctAnswer: "x = 3 or x = 4",
          explanation: "(x - 3)(x - 4) = 0.",
        },
        {
          questionText: "What is the discriminant of 3x^2 + 2x + 1 = 0?",
          type: "multiple_choice",
          options: ["-8", "16", "8", "-16"],
          correctAnswer: "-8",
          explanation: "b^2 - 4ac = 4 - 12 = -8.",
        },
        {
          questionText: "If the discriminant is zero, how many real roots does the equation have?",
          type: "multiple_choice",
          options: ["Two equal roots", "No real roots", "Two distinct roots", "One irrational root"],
          correctAnswer: "Two equal roots",
          explanation: "delta = 0 means two equal (repeated) real roots.",
        },
        {
          questionText: "Solve the inequality: x^2 - 4x - 5 > 0",
          type: "short_answer",
          correctAnswer: "x < -1 or x > 5",
          explanation: "(x + 1)(x - 5) > 0 gives x < -1 or x > 5.",
        },
        {
          questionText: "Solve simultaneously: y = 2x - 1 and x^2 + y = 7",
          type: "short_answer",
          correctAnswer: "x = -4, y = -9 or x = 2, y = 3",
          explanation: "Substitute: x^2 + 2x - 1 = 7, x^2 + 2x - 8 = 0, (x+4)(x-2) = 0.",
        },
      ],
    },
  },

  {
    key: "math11-number-patterns",
    title: "Number Patterns",
    description:
      "Quadratic number patterns, second differences, and finding the general term of a quadratic sequence.",
    grade: 11,
    order: 3,
    capsTags: ["number patterns", "quadratic sequences", "second differences", "general term"],
    lessons: [
      {
        title: "Quadratic Number Patterns",
        type: "text",
        order: 1,
        content: `# Quadratic Number Patterns

## First and Second Differences

A quadratic sequence has a constant second difference.

**Example:** 2, 6, 12, 20, 30, ...
First differences: 4, 6, 8, 10, ...
Second differences: 2, 2, 2, ... (constant)

## General Term

The general term is T_n = an^2 + bn + c

To find a, b, c:
1. 2a = second difference, so a = second difference / 2
2. 3a + b = first first-difference
3. a + b + c = T_1

**Example:** For 2, 6, 12, 20, ...
2a = 2 → a = 1
3(1) + b = 4 → b = 1
1 + 1 + c = 2 → c = 0
T_n = n^2 + n`,
      },
      {
        title: "Applications and Problem Solving",
        type: "text",
        order: 2,
        content: `# Applications of Quadratic Sequences

## Finding a Specific Term

Once you have T_n, substitute the value of n.

**Example:** T_n = n^2 + n. Find T_20.
T_20 = 400 + 20 = 420

## Finding Which Term Has a Given Value

Set T_n equal to the value and solve the quadratic.

**Example:** For T_n = n^2 + n, which term equals 110?
n^2 + n = 110
n^2 + n - 110 = 0
(n + 11)(n - 10) = 0
n = 10 (reject n = -11)

## Mixed Patterns

Always test whether the sequence is linear (constant first differences) or quadratic (constant second differences) before attempting the general term.`,
      },
    ],
    quiz: {
      title: "Number Patterns Quiz",
      description: "Quadratic sequences, second differences, and general terms.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the second difference of the sequence 1, 4, 9, 16, 25?",
          type: "multiple_choice",
          options: ["2", "3", "4", "5"],
          correctAnswer: "2",
          explanation: "First differences: 3, 5, 7, 9. Second differences: 2, 2, 2.",
        },
        {
          questionText: "If 2a = 6 for a quadratic sequence, what is a?",
          type: "short_answer",
          correctAnswer: "3",
          explanation: "a = 6 / 2 = 3.",
        },
        {
          questionText: "The general term of 3, 8, 15, 24, ... is?",
          type: "multiple_choice",
          options: ["n^2 + 2n", "n^2 + n + 1", "2n^2 + 1", "n^2 + 3n - 1"],
          correctAnswer: "n^2 + 2n",
          explanation: "Second diff = 2, a = 1. 3 + b = 5 → b = 2. 1 + 2 + c = 3 → c = 0.",
        },
        {
          questionText: "For T_n = 2n^2 - n, find T_5.",
          type: "short_answer",
          correctAnswer: "45",
          explanation: "T_5 = 2(25) - 5 = 50 - 5 = 45.",
        },
        {
          questionText: "A quadratic sequence has constant ___ differences.",
          type: "multiple_choice",
          options: ["second", "first", "third", "fourth"],
          correctAnswer: "second",
          explanation: "By definition, quadratic sequences have constant second differences.",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 2
  // ──────────────────────────────────────────

  {
    key: "math11-functions-graphs",
    title: "Functions and Graphs",
    description:
      "Parabola, hyperbola, and exponential functions with transformations, domain, range, and asymptotes.",
    grade: 11,
    order: 4,
    capsTags: [
      "functions",
      "parabola",
      "hyperbola",
      "exponential",
      "transformations",
      "asymptotes",
    ],
    lessons: [
      {
        title: "The Parabola: y = a(x - p)^2 + q",
        type: "text",
        order: 1,
        content: `# The Parabola

## Standard Form: y = a(x - p)^2 + q

- **Vertex (turning point):** (p, q)
- **Axis of symmetry:** x = p
- If a > 0: opens upward (minimum at q)
- If a < 0: opens downward (maximum at q)
- **Domain:** x in all real numbers
- **Range:** y >= q (if a > 0) or y <= q (if a < 0)

## Finding the Equation

Given vertex (p, q) and one other point, substitute to find a.

**Example:** Vertex (1, -3), passes through (3, 5).
y = a(x - 1)^2 - 3
5 = a(3 - 1)^2 - 3
5 = 4a - 3
a = 2
y = 2(x - 1)^2 - 3

## Key Features to Identify
- Turning point, axis of symmetry
- y-intercept (set x = 0)
- x-intercepts (set y = 0)
- Increasing and decreasing intervals`,
      },
      {
        title: "The Hyperbola: y = a/(x - p) + q",
        type: "text",
        order: 2,
        content: `# The Hyperbola

## Standard Form: y = a/(x - p) + q

- **Vertical asymptote:** x = p
- **Horizontal asymptote:** y = q
- **Domain:** x in R, x ≠ p
- **Range:** y in R, y ≠ q
- If a > 0: graph is in quadrants where (x-p) and (y-q) have the same sign
- If a < 0: graph is in quadrants where (x-p) and (y-q) have opposite signs

## Axes of Symmetry

The hyperbola has two axes of symmetry:
- y = x - p + q
- y = -(x - p) + q

## Example

y = 3/(x - 2) + 1
Vertical asymptote: x = 2
Horizontal asymptote: y = 1
y-intercept: y = 3/(0-2) + 1 = -3/2 + 1 = -1/2`,
      },
      {
        title: "The Exponential Function: y = a.b^(x-p) + q",
        type: "text",
        order: 3,
        content: `# The Exponential Function

## Standard Form: y = a.b^(x-p) + q  (b > 0, b ≠ 1)

- **Horizontal asymptote:** y = q
- If b > 1: exponential growth
- If 0 < b < 1: exponential decay
- **Domain:** x in all real numbers
- **Range:** y > q (if a > 0) or y < q (if a < 0)

## Key Features
- y-intercept: set x = 0
- x-intercept: set y = 0 (may not exist)
- The graph never touches the asymptote

## Example

y = 2^(x-1) + 3
Asymptote: y = 3
y-intercept: y = 2^(-1) + 3 = 0.5 + 3 = 3.5
The graph shifts 1 unit right and 3 units up from y = 2^x`,
      },
    ],
    quiz: {
      title: "Functions and Graphs Quiz",
      description: "Parabola, hyperbola, and exponential function properties.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the turning point of y = 2(x - 3)^2 + 5?",
          type: "multiple_choice",
          options: ["(3, 5)", "(-3, 5)", "(3, -5)", "(-3, -5)"],
          correctAnswer: "(3, 5)",
          explanation: "The vertex form y = a(x-p)^2 + q gives turning point (p, q) = (3, 5).",
        },
        {
          questionText: "What is the horizontal asymptote of y = 4/(x+1) - 2?",
          type: "short_answer",
          correctAnswer: "y = -2",
          explanation: "For y = a/(x-p) + q, the horizontal asymptote is y = q = -2.",
        },
        {
          questionText: "The range of y = -3(x+1)^2 + 4 is:",
          type: "multiple_choice",
          options: ["y <= 4", "y >= 4", "y <= -4", "y >= -4"],
          correctAnswer: "y <= 4",
          explanation: "a < 0 means the parabola opens downward, so maximum is q = 4.",
        },
        {
          questionText: "If y = 2^x is shifted 3 units down, the asymptote becomes:",
          type: "short_answer",
          correctAnswer: "y = -3",
          explanation: "y = 2^x + q, with q = -3, asymptote is y = -3.",
        },
        {
          questionText: "What is the vertical asymptote of y = 5/(x - 4) + 1?",
          type: "short_answer",
          correctAnswer: "x = 4",
          explanation: "The vertical asymptote is x = p = 4.",
        },
      ],
    },
  },

  {
    key: "math11-trigonometry",
    title: "Trigonometry",
    description:
      "Trigonometric identities, reduction formulae, equations, and graphs of sin, cos, and tan.",
    grade: 11,
    order: 5,
    capsTags: [
      "trigonometry",
      "identities",
      "reduction formulae",
      "trig equations",
      "trig graphs",
    ],
    lessons: [
      {
        title: "Trigonometric Identities",
        type: "text",
        order: 1,
        content: `# Trigonometric Identities

## Quotient Identity
tan(x) = sin(x) / cos(x)

## Squared Identity
sin^2(x) + cos^2(x) = 1

This gives:
- sin^2(x) = 1 - cos^2(x)
- cos^2(x) = 1 - sin^2(x)

## Proving Identities

Strategy:
1. Start with the more complex side.
2. Use known identities to simplify.
3. Show that LHS = RHS.

**Example:** Prove that (1 - sin^2(x)) / cos(x) = cos(x)
LHS = cos^2(x) / cos(x) = cos(x) = RHS ✓`,
      },
      {
        title: "Reduction Formulae and Negative Angles",
        type: "text",
        order: 2,
        content: `# Reduction Formulae

## Negative Angles
- sin(-x) = -sin(x)
- cos(-x) = cos(x)
- tan(-x) = -tan(x)

## Co-function Relationships (complementary angles)
- sin(90° - x) = cos(x)
- cos(90° - x) = sin(x)

## Quadrant Reductions
Use CAST diagram to determine signs:
- **A**ll positive in Q1
- **S**in positive in Q2
- **T**an positive in Q3
- **C**os positive in Q4

**Examples:**
- sin(180° - x) = sin(x)
- cos(180° + x) = -cos(x)
- tan(360° - x) = -tan(x)
- sin(90° + x) = cos(x)`,
      },
      {
        title: "Trigonometric Equations and Graphs",
        type: "text",
        order: 3,
        content: `# Trigonometric Equations

## General Solutions

For sin(x) = k:
x = sin^(-1)(k) + n.360° or x = 180° - sin^(-1)(k) + n.360°

For cos(x) = k:
x = ±cos^(-1)(k) + n.360°

For tan(x) = k:
x = tan^(-1)(k) + n.180°

**Example:** Solve 2sin(x) - 1 = 0
sin(x) = 1/2
x = 30° + n.360° or x = 150° + n.360°

# Trigonometric Graphs

## y = a.sin(bx + c) + d
- Amplitude: |a|
- Period: 360°/b
- Phase shift: -c/b (positive = left)
- Vertical shift: d`,
      },
    ],
    quiz: {
      title: "Trigonometry Quiz",
      description: "Identities, reduction formulae, equations, and graph properties.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Simplify: sin(180° + x)",
          type: "multiple_choice",
          options: ["-sin(x)", "sin(x)", "cos(x)", "-cos(x)"],
          correctAnswer: "-sin(x)",
          explanation: "In Q3, sin is negative: sin(180° + x) = -sin(x).",
        },
        {
          questionText: "Which identity is equivalent to 1 - cos^2(x)?",
          type: "multiple_choice",
          options: ["sin^2(x)", "tan^2(x)", "cos^2(x)", "1"],
          correctAnswer: "sin^2(x)",
          explanation: "From sin^2(x) + cos^2(x) = 1.",
        },
        {
          questionText: "What is the period of y = sin(2x)?",
          type: "short_answer",
          correctAnswer: "180°",
          explanation: "Period = 360°/b = 360°/2 = 180°.",
        },
        {
          questionText: "Solve for x in [0°, 360°]: cos(x) = -1/2",
          type: "short_answer",
          correctAnswer: "x = 120° or x = 240°",
          explanation: "Reference angle 60°, cos is negative in Q2 and Q3.",
        },
        {
          questionText: "sin(90° - x) equals:",
          type: "multiple_choice",
          options: ["cos(x)", "sin(x)", "-cos(x)", "tan(x)"],
          correctAnswer: "cos(x)",
          explanation: "Co-function identity: sin(90° - x) = cos(x).",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 3
  // ──────────────────────────────────────────

  {
    key: "math11-analytical-geometry",
    title: "Analytical Geometry",
    description:
      "Inclination of a line, equations of parallel and perpendicular lines, and properties of quadrilaterals using coordinates.",
    grade: 11,
    order: 6,
    capsTags: [
      "analytical geometry",
      "inclination",
      "parallel lines",
      "perpendicular lines",
      "quadrilaterals",
    ],
    lessons: [
      {
        title: "Inclination and Angle Between Lines",
        type: "text",
        order: 1,
        content: `# Inclination of a Line

The inclination (theta) is the angle a line makes with the positive x-axis.

## Relationship to Gradient
tan(theta) = m (gradient)

**Example:** A line with gradient m = 1 has inclination tan^(-1)(1) = 45°.
A line with gradient m = -1 has inclination 180° - 45° = 135° (since m < 0).

## Angle Between Two Lines

tan(alpha) = |(m1 - m2) / (1 + m1.m2)|

where m1 and m2 are the gradients of the two lines.

**Example:** Lines with gradients 2 and -1/3:
tan(alpha) = |(2 - (-1/3)) / (1 + 2(-1/3))|
= |(7/3) / (1/3)| = 7
alpha = tan^(-1)(7) ≈ 81.9°`,
      },
      {
        title: "Parallel, Perpendicular Lines and Quadrilateral Proofs",
        type: "text",
        order: 2,
        content: `# Parallel and Perpendicular Lines

## Parallel Lines
Two lines are parallel if and only if m1 = m2.

## Perpendicular Lines
Two lines are perpendicular if and only if m1 x m2 = -1.

## Equation of a Line Through a Point
Use point-gradient form: y - y1 = m(x - x1)

**Example:** Line through (2, 5) perpendicular to y = 3x + 1.
m_perp = -1/3
y - 5 = -1/3 (x - 2)
y = -x/3 + 2/3 + 5
y = -x/3 + 17/3

# Proving Quadrilateral Properties

Use distance, midpoint, and gradient formulas to prove that a quadrilateral is a:
- **Parallelogram:** opposite sides parallel (equal gradients)
- **Rectangle:** parallelogram with perpendicular adjacent sides
- **Rhombus:** parallelogram with all sides equal
- **Square:** rectangle with all sides equal
- **Kite:** two pairs of adjacent sides equal`,
      },
    ],
    quiz: {
      title: "Analytical Geometry Quiz",
      description: "Inclination, parallel/perpendicular lines, and coordinate geometry proofs.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is the inclination of a line with gradient sqrt(3)?",
          type: "multiple_choice",
          options: ["60°", "45°", "30°", "90°"],
          correctAnswer: "60°",
          explanation: "tan(60°) = sqrt(3).",
        },
        {
          questionText: "Two lines are perpendicular. If one has gradient 2, the other has gradient:",
          type: "short_answer",
          correctAnswer: "-1/2",
          explanation: "m1 x m2 = -1, so m2 = -1/2.",
        },
        {
          questionText: "Lines with gradients 3/4 and 3/4 are:",
          type: "multiple_choice",
          options: ["Parallel", "Perpendicular", "Neither", "Coincident"],
          correctAnswer: "Parallel",
          explanation: "Equal gradients means parallel.",
        },
        {
          questionText: "Find the equation of the line through (1, 4) with gradient -2.",
          type: "short_answer",
          correctAnswer: "y = -2x + 6",
          explanation: "y - 4 = -2(x - 1), y = -2x + 2 + 4 = -2x + 6.",
        },
        {
          questionText: "To prove a quadrilateral is a rhombus, you must show:",
          type: "multiple_choice",
          options: [
            "All four sides are equal",
            "Opposite sides are parallel",
            "All angles are 90°",
            "Diagonals bisect each other",
          ],
          correctAnswer: "All four sides are equal",
          explanation: "A rhombus has all sides equal in length.",
        },
      ],
    },
  },

  {
    key: "math11-euclidean-geometry",
    title: "Euclidean Geometry",
    description:
      "Circle geometry theorems including tangent-radius, angles subtended by arcs, and cyclic quadrilaterals.",
    grade: 11,
    order: 7,
    capsTags: [
      "euclidean geometry",
      "circle theorems",
      "tangent",
      "cyclic quadrilateral",
      "angles in a circle",
    ],
    lessons: [
      {
        title: "Circle Theorems: Central and Inscribed Angles",
        type: "text",
        order: 1,
        content: `# Circle Theorems

## Theorem 1: Line from Centre to Midpoint of Chord
The line drawn from the centre of a circle perpendicular to a chord bisects the chord, and conversely.

## Theorem 2: Angle at Centre = 2 x Angle at Circumference
The angle subtended by an arc at the centre equals twice the angle subtended at the circumference.

## Theorem 3: Angles in the Same Segment
Angles subtended by the same arc (or chord) at the circumference are equal.

## Theorem 4: Angle in a Semicircle
The angle subtended by a diameter at the circumference is 90°.

## Theorem 5: Opposite Angles of a Cyclic Quadrilateral
The opposite angles of a cyclic quadrilateral are supplementary (add to 180°).`,
      },
      {
        title: "Tangent Theorems and Proofs",
        type: "text",
        order: 2,
        content: `# Tangent Theorems

## Theorem 6: Tangent Perpendicular to Radius
A tangent to a circle is perpendicular to the radius at the point of tangency.

## Theorem 7: Two Tangents from External Point
Two tangents drawn from the same external point are equal in length.

## Theorem 8: Tangent-Chord Angle
The angle between a tangent and a chord equals the inscribed angle on the opposite side of the chord.

## Writing Proofs

When proving circle geometry:
1. State the theorem you are using.
2. Reference the diagram clearly.
3. Give reasons for each statement.

**Example statement:** "Angle ABC = Angle ADC (angles in the same segment)"`,
      },
    ],
    quiz: {
      title: "Euclidean Geometry Quiz",
      description: "Circle theorems, tangent properties, and cyclic quadrilaterals.",
      difficulty: "hard",
      questions: [
        {
          questionText: "The angle at the centre is ___ the angle at the circumference.",
          type: "multiple_choice",
          options: ["Twice", "Half", "Equal to", "Three times"],
          correctAnswer: "Twice",
          explanation: "Central angle = 2 x inscribed angle (same arc).",
        },
        {
          questionText: "Opposite angles of a cyclic quadrilateral sum to:",
          type: "short_answer",
          correctAnswer: "180°",
          explanation: "Opposite angles of a cyclic quad are supplementary.",
        },
        {
          questionText: "A tangent to a circle is ___ to the radius at the point of contact.",
          type: "multiple_choice",
          options: ["Perpendicular", "Parallel", "Equal", "Bisecting"],
          correctAnswer: "Perpendicular",
          explanation: "The tangent-radius theorem states they are perpendicular.",
        },
        {
          questionText: "An angle in a semicircle equals:",
          type: "short_answer",
          correctAnswer: "90°",
          explanation: "The angle subtended by a diameter at the circumference is 90°.",
        },
        {
          questionText: "Two tangents from the same external point are:",
          type: "multiple_choice",
          options: ["Equal in length", "Perpendicular", "Parallel", "Supplementary"],
          correctAnswer: "Equal in length",
          explanation: "Two tangents from the same external point to a circle are equal.",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 4
  // ──────────────────────────────────────────

  {
    key: "math11-statistics",
    title: "Statistics",
    description:
      "Measures of central tendency and dispersion, cumulative frequency, ogives, box-and-whisker plots, and variance.",
    grade: 11,
    order: 8,
    capsTags: [
      "statistics",
      "ogive",
      "box-and-whisker",
      "standard deviation",
      "variance",
      "percentiles",
    ],
    lessons: [
      {
        title: "Measures of Central Tendency and Dispersion",
        type: "text",
        order: 1,
        content: `# Statistics: Measures

## Central Tendency
- **Mean:** sum of values / number of values
- **Median:** middle value when data is ordered
- **Mode:** most frequently occurring value

## Measures of Dispersion
- **Range:** max - min
- **Interquartile Range (IQR):** Q3 - Q1
- **Variance:** sigma^2 = sum((x_i - mean)^2) / n
- **Standard Deviation:** sigma = sqrt(variance)

## Five-Number Summary
Minimum, Q1, Median, Q3, Maximum

## Box-and-Whisker Plot
Uses the five-number summary. The box spans Q1 to Q3. Whiskers extend to min and max. Outliers are plotted individually.

## Outliers
A value is an outlier if it is:
- Less than Q1 - 1.5 x IQR, or
- Greater than Q3 + 1.5 x IQR`,
      },
      {
        title: "Cumulative Frequency and Ogives",
        type: "text",
        order: 2,
        content: `# Cumulative Frequency

## Grouped Data

For grouped data, use class midpoints to estimate the mean:
mean ≈ sum(frequency x midpoint) / sum(frequency)

## Ogive (Cumulative Frequency Curve)

Steps:
1. Create a cumulative frequency table.
2. Plot cumulative frequency against upper class boundaries.
3. Join points with a smooth curve.

## Reading Values from an Ogive
- **Median:** value at 50% of total frequency
- **Q1:** value at 25% of total frequency
- **Q3:** value at 75% of total frequency
- **Percentiles:** value at the given percentage

## Symmetric vs Skewed Distributions
- Symmetric: mean ≈ median
- Positively skewed: mean > median (tail to right)
- Negatively skewed: mean < median (tail to left)`,
      },
    ],
    quiz: {
      title: "Statistics Quiz",
      description: "Central tendency, dispersion, ogives, and box-and-whisker plots.",
      difficulty: "medium",
      questions: [
        {
          questionText: "The standard deviation is the square root of the:",
          type: "multiple_choice",
          options: ["Variance", "Mean", "Range", "IQR"],
          correctAnswer: "Variance",
          explanation: "sigma = sqrt(variance).",
        },
        {
          questionText: "What is the IQR if Q1 = 20 and Q3 = 45?",
          type: "short_answer",
          correctAnswer: "25",
          explanation: "IQR = Q3 - Q1 = 45 - 20 = 25.",
        },
        {
          questionText: "An ogive is a graph of:",
          type: "multiple_choice",
          options: ["Cumulative frequency", "Frequency", "Relative frequency", "Standard deviation"],
          correctAnswer: "Cumulative frequency",
          explanation: "An ogive plots cumulative frequency against upper class boundaries.",
        },
        {
          questionText: "If mean > median, the distribution is:",
          type: "multiple_choice",
          options: ["Positively skewed", "Negatively skewed", "Symmetric", "Bimodal"],
          correctAnswer: "Positively skewed",
          explanation: "Mean > median indicates a tail to the right (positive skew).",
        },
        {
          questionText: "A value is an outlier if it lies beyond Q1 - ___ x IQR or Q3 + ___ x IQR.",
          type: "short_answer",
          correctAnswer: "1.5",
          explanation: "The standard outlier rule uses 1.5 x IQR.",
        },
      ],
    },
  },

  {
    key: "math11-probability",
    title: "Probability",
    description:
      "Dependent and independent events, Venn diagrams, tree diagrams, and the addition and product rules.",
    grade: 11,
    order: 9,
    capsTags: [
      "probability",
      "independent events",
      "dependent events",
      "venn diagrams",
      "tree diagrams",
    ],
    lessons: [
      {
        title: "Probability Rules and Venn Diagrams",
        type: "text",
        order: 1,
        content: `# Probability

## Basic Rules
- P(A) is between 0 and 1
- P(not A) = 1 - P(A)
- P(A or B) = P(A) + P(B) - P(A and B)  (Addition Rule)
- If A and B are mutually exclusive: P(A and B) = 0

## Venn Diagrams

Draw overlapping circles for events A and B inside a rectangle (sample space).

Regions:
- Only A: P(A) - P(A and B)
- Only B: P(B) - P(A and B)
- A and B: P(A and B)
- Neither: 1 - P(A or B)

## Complementary Events
P(at least one) = 1 - P(none)`,
      },
      {
        title: "Independent and Dependent Events",
        type: "text",
        order: 2,
        content: `# Independent and Dependent Events

## Independent Events
Events A and B are independent if the occurrence of one does not affect the other.

Test: P(A and B) = P(A) x P(B)

**Example:** Rolling a 6 on a die and getting heads on a coin.
P(6 and H) = 1/6 x 1/2 = 1/12

## Dependent Events
If the outcome of one event affects the other.

**Example:** Drawing two cards without replacement.
P(both aces) = 4/52 x 3/51

## Tree Diagrams
Useful for sequential events. Multiply along branches, add across branches for combined probabilities.

## Contingency Tables
Two-way tables showing frequencies. Calculate probabilities by reading row/column totals.`,
      },
    ],
    quiz: {
      title: "Probability Quiz",
      description: "Independent/dependent events, Venn diagrams, and probability rules.",
      difficulty: "medium",
      questions: [
        {
          questionText: "P(A or B) = P(A) + P(B) - P(A and B) is called the:",
          type: "multiple_choice",
          options: ["Addition rule", "Product rule", "Complement rule", "Bayes' theorem"],
          correctAnswer: "Addition rule",
          explanation: "This is the addition (or inclusion-exclusion) rule.",
        },
        {
          questionText: "If P(A) = 0.3 and P(B) = 0.5 and they are independent, P(A and B) = ?",
          type: "short_answer",
          correctAnswer: "0.15",
          explanation: "P(A and B) = P(A) x P(B) = 0.3 x 0.5 = 0.15.",
        },
        {
          questionText: "Two events are mutually exclusive if:",
          type: "multiple_choice",
          options: [
            "P(A and B) = 0",
            "P(A and B) = P(A) x P(B)",
            "P(A or B) = 0",
            "P(A) + P(B) = 1",
          ],
          correctAnswer: "P(A and B) = 0",
          explanation: "Mutually exclusive means they cannot happen at the same time.",
        },
        {
          questionText: "P(not A) = 1 - P(A) is called the:",
          type: "multiple_choice",
          options: ["Complement rule", "Addition rule", "Product rule", "Conditional rule"],
          correctAnswer: "Complement rule",
          explanation: "The complement rule relates P(A) and P(not A).",
        },
        {
          questionText: "Drawing cards without replacement results in ___ events.",
          type: "multiple_choice",
          options: ["Dependent", "Independent", "Mutually exclusive", "Complementary"],
          correctAnswer: "Dependent",
          explanation: "Without replacement changes the probability, making events dependent.",
        },
      ],
    },
  },

  {
    key: "math11-finance",
    title: "Finance, Growth and Decay",
    description:
      "Simple and compound interest, depreciation, nominal and effective interest rates, and timelines.",
    grade: 11,
    order: 10,
    capsTags: [
      "finance",
      "simple interest",
      "compound interest",
      "depreciation",
      "nominal rate",
      "effective rate",
    ],
    lessons: [
      {
        title: "Simple and Compound Interest",
        type: "text",
        order: 1,
        content: `# Financial Mathematics

## Simple Interest
A = P(1 + in)
- A = final amount, P = principal, i = interest rate, n = time in years

**Example:** R5000 at 8% simple interest for 3 years.
A = 5000(1 + 0.08 x 3) = 5000(1.24) = R6200

## Compound Interest
A = P(1 + i)^n

**Example:** R5000 at 8% compound interest for 3 years.
A = 5000(1.08)^3 = 5000(1.259712) = R6298.56

## Depreciation

### Straight-line (simple): A = P(1 - in)
### Reducing balance (compound): A = P(1 - i)^n

**Example:** A car worth R200,000 depreciates at 15% per year (reducing balance) for 5 years.
A = 200000(0.85)^5 = R88,735.08`,
      },
      {
        title: "Nominal and Effective Interest Rates",
        type: "text",
        order: 2,
        content: `# Nominal and Effective Rates

## Nominal Rate
The stated annual rate, compounded m times per year.
Written as i_nominal = r% p.a. compounded monthly/quarterly/etc.

## Effective Rate
The equivalent rate if compounding happened once per year.

Formula: 1 + i_eff = (1 + i_nominal/m)^m

**Example:** 12% p.a. compounded monthly:
i_eff = (1 + 0.12/12)^12 - 1 = (1.01)^12 - 1 ≈ 0.1268 = 12.68%

## Converting Effective to Nominal
i_nominal = m[(1 + i_eff)^(1/m) - 1]

## Timelines
Use a timeline to visualise when deposits, withdrawals, and interest periods occur.
Always convert the interest rate to match the compounding period.`,
      },
    ],
    quiz: {
      title: "Finance, Growth and Decay Quiz",
      description: "Interest, depreciation, and nominal/effective rate conversions.",
      difficulty: "medium",
      questions: [
        {
          questionText: "The compound interest formula is:",
          type: "multiple_choice",
          options: ["A = P(1+i)^n", "A = P(1+in)", "A = P(1-i)^n", "A = P(1-in)"],
          correctAnswer: "A = P(1+i)^n",
          explanation: "Compound interest: A = P(1+i)^n.",
        },
        {
          questionText: "R10 000 at 6% compound interest for 2 years gives:",
          type: "short_answer",
          correctAnswer: "R11 236",
          explanation: "A = 10000(1.06)^2 = 10000(1.1236) = R11 236.",
        },
        {
          questionText: "Reducing-balance depreciation uses the formula:",
          type: "multiple_choice",
          options: ["A = P(1-i)^n", "A = P(1+i)^n", "A = P(1-in)", "A = P(1+in)"],
          correctAnswer: "A = P(1-i)^n",
          explanation: "Reducing balance depreciation: A = P(1-i)^n.",
        },
        {
          questionText: "What does 'compounded quarterly' mean?",
          type: "multiple_choice",
          options: ["Interest added 4 times per year", "Interest added once per year", "Interest added 12 times per year", "Interest added daily"],
          correctAnswer: "Interest added 4 times per year",
          explanation: "Quarterly = 4 times per year (every 3 months).",
        },
        {
          questionText: "The effective annual rate is always ___ than the nominal rate (if compounding more than once).",
          type: "multiple_choice",
          options: ["Greater", "Less", "Equal", "Half"],
          correctAnswer: "Greater",
          explanation: "More frequent compounding results in a higher effective rate.",
        },
      ],
    },
  },
];
