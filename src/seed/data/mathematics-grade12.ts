import type { ModuleSeed } from "../types.js";

export const grade12Modules: ModuleSeed[] = [
  // ──────────────────────────────────────────
  // TERM 1
  // ──────────────────────────────────────────

  {
    key: "math12-sequences-series",
    title: "Sequences and Series",
    description:
      "Arithmetic and geometric sequences, the sum formulas, sigma notation, and convergence of geometric series.",
    grade: 12,
    order: 1,
    capsTags: [
      "sequences",
      "series",
      "arithmetic",
      "geometric",
      "sigma notation",
      "convergence",
    ],
    lessons: [
      {
        title: "Arithmetic Sequences and Series",
        type: "text",
        order: 1,
        content: `# Arithmetic Sequences and Series

## Arithmetic Sequence
A sequence with a constant common difference d.

T_n = a + (n - 1)d

where a = first term, d = common difference.

**Example:** 3, 7, 11, 15, ...
a = 3, d = 4
T_n = 3 + (n-1)(4) = 4n - 1

## Arithmetic Series (Sum)

S_n = n/2 (2a + (n-1)d)  or  S_n = n/2 (a + l)

where l = last term.

**Example:** Sum of the first 20 terms of 3, 7, 11, ...
S_20 = 20/2 (2(3) + 19(4)) = 10(6 + 76) = 10(82) = 820`,
      },
      {
        title: "Geometric Sequences and Series",
        type: "text",
        order: 2,
        content: `# Geometric Sequences and Series

## Geometric Sequence
A sequence with a constant common ratio r.

T_n = a . r^(n-1)

**Example:** 2, 6, 18, 54, ...
a = 2, r = 3
T_n = 2 . 3^(n-1)

## Geometric Series (Sum of n terms)

S_n = a(r^n - 1) / (r - 1)   if r ≠ 1

**Example:** Sum of first 5 terms of 2, 6, 18, 54, ...
S_5 = 2(3^5 - 1)/(3 - 1) = 2(243 - 1)/2 = 242

## Sum to Infinity (Convergent Series)

If |r| < 1, the series converges:
S_infinity = a / (1 - r)

**Example:** 8 + 4 + 2 + 1 + ...
r = 1/2, S_infinity = 8 / (1 - 1/2) = 16`,
      },
      {
        title: "Sigma Notation and Mixed Problems",
        type: "text",
        order: 3,
        content: `# Sigma Notation

## Writing a Series in Sigma Notation

sum from k=1 to n of T_k

**Example:** 3 + 5 + 7 + ... + 21
T_k = 2k + 1, from k=1 to k=10
Written: Σ(k=1 to 10) (2k + 1)

## Mixed Problems

To determine if a sequence is arithmetic or geometric:
- Arithmetic: check T_2 - T_1 = T_3 - T_2 (constant difference)
- Geometric: check T_2/T_1 = T_3/T_2 (constant ratio)

## Finding n Given S_n

Set S_n equal to the given sum and solve for n.

**Example:** For S_n = n/2 (4n + 2), find n when S_n = 110.
n/2 (4n + 2) = 110
n(2n + 1) = 110
2n^2 + n - 110 = 0
(2n + 15)(n - 7) ≈ ... → n = 7 (verify by checking)`,
      },
    ],
    quiz: {
      title: "Sequences and Series Quiz",
      description: "Arithmetic, geometric sequences, series, sigma notation, and convergence.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Find T_10 of the arithmetic sequence 5, 9, 13, ...",
          type: "multiple_choice",
          options: ["41", "45", "37", "49"],
          correctAnswer: "41",
          explanation: "T_n = 5 + (n-1)(4). T_10 = 5 + 36 = 41.",
        },
        {
          questionText: "What is the common ratio of 3, 12, 48, 192?",
          type: "short_answer",
          correctAnswer: "4",
          explanation: "r = 12/3 = 4.",
        },
        {
          questionText: "A geometric series converges when:",
          type: "multiple_choice",
          options: ["|r| < 1", "|r| > 1", "r = 1", "r = 0"],
          correctAnswer: "|r| < 1",
          explanation: "The series converges only when the absolute value of r is less than 1.",
        },
        {
          questionText: "Find S_infinity of 10 + 5 + 2.5 + ...",
          type: "short_answer",
          correctAnswer: "20",
          explanation: "r = 0.5, S_inf = 10 / (1 - 0.5) = 20.",
        },
        {
          questionText: "S_n = n/2 (a + l) is used for ___ series.",
          type: "multiple_choice",
          options: ["Arithmetic", "Geometric", "Harmonic", "Fibonacci"],
          correctAnswer: "Arithmetic",
          explanation: "This is the arithmetic series formula using first and last terms.",
        },
      ],
    },
  },

  {
    key: "math12-functions-inverses",
    title: "Functions: Inverses",
    description:
      "Inverse functions, logarithms, and the relationship between exponential and logarithmic functions.",
    grade: 12,
    order: 2,
    capsTags: [
      "inverse functions",
      "logarithms",
      "exponential",
      "reflection",
    ],
    lessons: [
      {
        title: "Inverse Functions and the Line y = x",
        type: "text",
        order: 1,
        content: `# Inverse Functions

## Definition
The inverse of f is obtained by swapping x and y.
The graph of the inverse is a reflection of f in the line y = x.

## Finding the Inverse
1. Write y = f(x).
2. Swap x and y.
3. Solve for y.

## Inverse of y = ax + q (Linear)
Swap: x = ay + q → y = (x - q)/a
The inverse of a linear function is linear.

## Inverse of y = ax^2 (Quadratic)
Swap: x = ay^2 → y = ±sqrt(x/a)
The inverse is NOT a function (fails vertical line test).
Restrict the domain to x >= 0 or x <= 0 to make it a function.

## One-to-One Functions
Only one-to-one functions have inverses that are also functions.
Use the horizontal line test to check.`,
      },
      {
        title: "Logarithmic and Exponential Functions",
        type: "text",
        order: 2,
        content: `# Logarithmic Functions

## Inverse of y = b^x
Swap: x = b^y → y = log_b(x)

So the logarithmic function is the inverse of the exponential function.

## Logarithm Laws
- log_b(mn) = log_b(m) + log_b(n)
- log_b(m/n) = log_b(m) - log_b(n)
- log_b(m^p) = p . log_b(m)
- log_b(1) = 0
- log_b(b) = 1

## Solving Logarithmic Equations

**Example:** log_2(x) = 5
x = 2^5 = 32

## Graphs
- y = b^x: exponential growth (b > 1), passes through (0, 1)
- y = log_b(x): its reflection in y = x, passes through (1, 0)
- Both share the same domain-range swap`,
      },
    ],
    quiz: {
      title: "Functions: Inverses Quiz",
      description: "Inverse functions, logarithms, and their relationship to exponentials.",
      difficulty: "medium",
      questions: [
        {
          questionText: "The inverse of a function is reflected in:",
          type: "multiple_choice",
          options: ["y = x", "y-axis", "x-axis", "Origin"],
          correctAnswer: "y = x",
          explanation: "The inverse is a reflection in the line y = x.",
        },
        {
          questionText: "What is log_3(81)?",
          type: "short_answer",
          correctAnswer: "4",
          explanation: "3^4 = 81, so log_3(81) = 4.",
        },
        {
          questionText: "The inverse of y = 2x + 6 is:",
          type: "multiple_choice",
          options: ["y = (x-6)/2", "y = 2x - 6", "y = -2x + 6", "y = x/2 - 3"],
          correctAnswer: "y = (x-6)/2",
          explanation: "x = 2y + 6 → y = (x-6)/2.",
        },
        {
          questionText: "log_b(1) equals:",
          type: "short_answer",
          correctAnswer: "0",
          explanation: "b^0 = 1 for any b > 0, b ≠ 1.",
        },
        {
          questionText: "The inverse of y = x^2 (x >= 0) is:",
          type: "multiple_choice",
          options: ["y = sqrt(x)", "y = x^2", "y = -sqrt(x)", "y = 1/x^2"],
          correctAnswer: "y = sqrt(x)",
          explanation: "With restriction x >= 0, the inverse is y = sqrt(x).",
        },
      ],
    },
  },

  {
    key: "math12-finance",
    title: "Financial Mathematics",
    description:
      "Future value and present value annuities, sinking funds, loan repayments, and deferred payments.",
    grade: 12,
    order: 3,
    capsTags: [
      "annuities",
      "future value",
      "present value",
      "sinking fund",
      "loan repayment",
    ],
    lessons: [
      {
        title: "Future Value Annuity",
        type: "text",
        order: 1,
        content: `# Future Value Annuity

## Definition
Equal payments made at regular intervals into an account earning compound interest.

## Formula
F = x[(1 + i)^n - 1] / i

where:
- F = future value
- x = regular payment
- i = interest rate per period
- n = number of payments

**Example:** Save R500 per month at 9% p.a. compounded monthly for 5 years.
i = 0.09/12 = 0.0075, n = 60
F = 500[(1.0075)^60 - 1] / 0.0075
F = 500[1.5657 - 1] / 0.0075
F ≈ R37 752.78

## Sinking Fund
A future value annuity used to save for replacing an asset.
Calculate the required monthly deposit to reach a target amount.`,
      },
      {
        title: "Present Value Annuity and Loan Repayments",
        type: "text",
        order: 2,
        content: `# Present Value Annuity

## Formula
P = x[1 - (1 + i)^(-n)] / i

where:
- P = present value (loan amount)
- x = regular payment
- i = interest rate per period
- n = number of payments

**Example:** A home loan of R800 000 at 11% p.a. compounded monthly over 20 years.
i = 0.11/12, n = 240
x = P . i / [1 - (1 + i)^(-n)]
x ≈ R8 256.42 per month

## Balance Outstanding
After k payments, the balance is:
B = x[1 - (1 + i)^(-(n-k))] / i

## Total Interest Paid
Total interest = (x . n) - P

## Deferred Payments
If payments start after a grace period, accumulate interest on the principal during the deferral, then apply the annuity formula.`,
      },
    ],
    quiz: {
      title: "Financial Mathematics Quiz",
      description: "Annuities, sinking funds, and loan calculations.",
      difficulty: "hard",
      questions: [
        {
          questionText: "The future value annuity formula is:",
          type: "multiple_choice",
          options: [
            "F = x[(1+i)^n - 1] / i",
            "F = x[1 - (1+i)^(-n)] / i",
            "F = P(1+i)^n",
            "F = P(1+in)",
          ],
          correctAnswer: "F = x[(1+i)^n - 1] / i",
          explanation: "This gives the future value of regular equal payments.",
        },
        {
          questionText: "A sinking fund is an example of a ___ annuity.",
          type: "multiple_choice",
          options: ["Future value", "Present value", "Deferred", "Perpetuity"],
          correctAnswer: "Future value",
          explanation: "A sinking fund saves towards a future target amount.",
        },
        {
          questionText: "For a loan, which annuity formula is used?",
          type: "multiple_choice",
          options: ["Present value", "Future value", "Simple interest", "Compound growth"],
          correctAnswer: "Present value",
          explanation: "Loans are present value annuities: you receive money now and pay it back.",
        },
        {
          questionText: "Total interest on a loan = (monthly payment x n) minus ___.",
          type: "short_answer",
          correctAnswer: "The loan amount (P)",
          explanation: "Total paid minus principal gives total interest.",
        },
        {
          questionText: "If payments are deferred by 6 months, during that time the principal:",
          type: "multiple_choice",
          options: ["Grows with compound interest", "Stays the same", "Decreases", "Is forgiven"],
          correctAnswer: "Grows with compound interest",
          explanation: "Interest accrues during the deferral period, increasing the effective loan.",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 2
  // ──────────────────────────────────────────

  {
    key: "math12-trigonometry",
    title: "Trigonometry: Compound and Double Angles",
    description:
      "Compound angle formulae, double angle identities, solving trig equations, and 2D/3D trigonometric problems.",
    grade: 12,
    order: 4,
    capsTags: [
      "compound angles",
      "double angles",
      "trig equations",
      "sine rule",
      "cosine rule",
      "area rule",
    ],
    lessons: [
      {
        title: "Compound and Double Angle Formulae",
        type: "text",
        order: 1,
        content: `# Compound Angle Formulae

cos(A - B) = cosA.cosB + sinA.sinB
cos(A + B) = cosA.cosB - sinA.sinB
sin(A - B) = sinA.cosB - cosA.sinB
sin(A + B) = sinA.cosB + cosA.sinB

# Double Angle Formulae (let B = A)

sin(2A) = 2sinA.cosA

cos(2A) = cos^2(A) - sin^2(A)
         = 2cos^2(A) - 1
         = 1 - 2sin^2(A)

**Example:** Express sin(75°) using compound angles.
sin(75°) = sin(45° + 30°)
= sin45°.cos30° + cos45°.sin30°
= (sqrt(2)/2)(sqrt(3)/2) + (sqrt(2)/2)(1/2)
= (sqrt(6) + sqrt(2)) / 4`,
      },
      {
        title: "Sine, Cosine, and Area Rules for 2D and 3D",
        type: "text",
        order: 2,
        content: `# Triangle Rules

## Sine Rule
a/sinA = b/sinB = c/sinC

Used when: two angles and a side, or two sides and an angle opposite one of them.

## Cosine Rule
a^2 = b^2 + c^2 - 2bc.cosA

Used when: two sides and the included angle, or all three sides.

## Area Rule
Area = 1/2 . a . b . sinC

## 3D Problems
- Draw the figure and identify the relevant triangles.
- Work in one triangle at a time.
- Use the rules above for non-right-angled triangles.
- Use basic trig (SOHCAHTOA) for right-angled triangles.

**Example:** Angles of elevation and depression:
- Angle of elevation: measured upward from horizontal
- Angle of depression: measured downward from horizontal`,
      },
    ],
    quiz: {
      title: "Trigonometry: Compound Angles Quiz",
      description: "Compound angles, double angles, sine/cosine/area rules.",
      difficulty: "hard",
      questions: [
        {
          questionText: "sin(2A) equals:",
          type: "multiple_choice",
          options: ["2sinA.cosA", "sin^2(A) + cos^2(A)", "2sin^2(A)", "sinA + cosA"],
          correctAnswer: "2sinA.cosA",
          explanation: "The double angle formula for sine.",
        },
        {
          questionText: "cos(A+B) = cosA.cosB ___ sinA.sinB",
          type: "multiple_choice",
          options: ["minus", "plus", "times", "divided by"],
          correctAnswer: "minus",
          explanation: "cos(A+B) = cosA.cosB - sinA.sinB.",
        },
        {
          questionText: "The cosine rule is used when you have:",
          type: "multiple_choice",
          options: [
            "Two sides and the included angle",
            "Two angles and a side",
            "One side only",
            "Three angles",
          ],
          correctAnswer: "Two sides and the included angle",
          explanation: "The cosine rule requires SAS (or SSS).",
        },
        {
          questionText: "Area of a triangle = 1/2 . a . b . ___",
          type: "short_answer",
          correctAnswer: "sinC",
          explanation: "Area rule: 1/2 . a . b . sinC where C is the included angle.",
        },
        {
          questionText: "Which is a valid form of cos(2A)?",
          type: "multiple_choice",
          options: ["1 - 2sin^2(A)", "2sinA.cosA", "sin^2(A) + cos^2(A)", "2cosA"],
          correctAnswer: "1 - 2sin^2(A)",
          explanation: "cos(2A) = 1 - 2sin^2(A) is one of the three forms.",
        },
      ],
    },
  },

  {
    key: "math12-polynomials",
    title: "Polynomials",
    description:
      "Remainder theorem, factor theorem, and solving cubic equations by factorisation.",
    grade: 12,
    order: 5,
    capsTags: ["polynomials", "factor theorem", "remainder theorem", "cubic equations"],
    lessons: [
      {
        title: "Remainder and Factor Theorems",
        type: "text",
        order: 1,
        content: `# Polynomials

## Remainder Theorem
If a polynomial f(x) is divided by (x - a), the remainder is f(a).

**Example:** f(x) = x^3 - 2x^2 + x + 1, divided by (x - 2).
Remainder = f(2) = 8 - 8 + 2 + 1 = 3

## Factor Theorem
(x - a) is a factor of f(x) if and only if f(a) = 0.

**Example:** Is (x - 1) a factor of x^3 - 3x^2 + 2x?
f(1) = 1 - 3 + 2 = 0 ✓ Yes.

## Solving Cubic Equations

1. Use trial and error (try f(±1), f(±2), f(±3), ...) to find one root.
2. Use long division or synthetic division to get a quadratic factor.
3. Factorise the quadratic.

**Example:** x^3 - 6x^2 + 11x - 6 = 0
f(1) = 1 - 6 + 11 - 6 = 0, so (x - 1) is a factor.
Divide: x^3 - 6x^2 + 11x - 6 = (x - 1)(x^2 - 5x + 6) = (x-1)(x-2)(x-3)
Solutions: x = 1, 2, 3`,
      },
    ],
    quiz: {
      title: "Polynomials Quiz",
      description: "Factor theorem, remainder theorem, and cubic equations.",
      difficulty: "medium",
      questions: [
        {
          questionText: "If f(3) = 0, then (x - 3) is a ___ of f(x).",
          type: "multiple_choice",
          options: ["Factor", "Remainder", "Root", "Coefficient"],
          correctAnswer: "Factor",
          explanation: "By the factor theorem, f(a) = 0 means (x-a) is a factor.",
        },
        {
          questionText: "The remainder when f(x) = x^2 + 3x - 1 is divided by (x - 2) is:",
          type: "short_answer",
          correctAnswer: "9",
          explanation: "f(2) = 4 + 6 - 1 = 9.",
        },
        {
          questionText: "To solve a cubic equation, first find a root by:",
          type: "multiple_choice",
          options: ["Trial and error", "Quadratic formula", "Completing the square", "Graphing only"],
          correctAnswer: "Trial and error",
          explanation: "Try integer values to find f(a) = 0, then divide.",
        },
        {
          questionText: "After finding one linear factor of a cubic, the quotient is:",
          type: "multiple_choice",
          options: ["A quadratic", "A linear", "A cubic", "A constant"],
          correctAnswer: "A quadratic",
          explanation: "Cubic ÷ linear = quadratic.",
        },
        {
          questionText: "Factorise: x^3 - x",
          type: "short_answer",
          correctAnswer: "x(x-1)(x+1)",
          explanation: "x^3 - x = x(x^2 - 1) = x(x-1)(x+1).",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 3
  // ──────────────────────────────────────────

  {
    key: "math12-differential-calculus",
    title: "Differential Calculus",
    description:
      "Limits, first principles, differentiation rules, tangent lines, and optimisation (maxima and minima).",
    grade: 12,
    order: 6,
    capsTags: [
      "calculus",
      "differentiation",
      "first principles",
      "tangent",
      "optimisation",
      "cubic graphs",
    ],
    lessons: [
      {
        title: "Limits and Differentiation from First Principles",
        type: "text",
        order: 1,
        content: `# Differential Calculus

## Average Gradient
The gradient between two points on a curve:
m_avg = [f(x + h) - f(x)] / h

## Limit and First Principles
f'(x) = lim(h→0) [f(x + h) - f(x)] / h

**Example:** f(x) = x^2
f'(x) = lim(h→0) [(x+h)^2 - x^2] / h
= lim(h→0) [x^2 + 2xh + h^2 - x^2] / h
= lim(h→0) [2xh + h^2] / h
= lim(h→0) (2x + h)
= 2x

## Differentiation Rules

| Rule | Formula |
|---|---|
| Power rule | d/dx [x^n] = nx^(n-1) |
| Constant | d/dx [c] = 0 |
| Constant multiple | d/dx [cf(x)] = cf'(x) |
| Sum/Difference | d/dx [f ± g] = f' ± g' |`,
      },
      {
        title: "Equations of Tangent Lines",
        type: "text",
        order: 2,
        content: `# Tangent Lines

## Finding the Equation of a Tangent

1. Find f'(x) by differentiating.
2. Calculate the gradient at the point: m = f'(a).
3. Use point-gradient form: y - f(a) = m(x - a).

**Example:** Find the tangent to f(x) = x^3 - 3x at x = 2.
f'(x) = 3x^2 - 3
f'(2) = 12 - 3 = 9
f(2) = 8 - 6 = 2
Tangent: y - 2 = 9(x - 2) → y = 9x - 16

## Normal Line
The normal is perpendicular to the tangent.
m_normal = -1/m_tangent`,
      },
      {
        title: "Cubic Graphs and Optimisation",
        type: "text",
        order: 3,
        content: `# Cubic Graphs

## Sketching f(x) = ax^3 + bx^2 + cx + d

Steps:
1. Find the y-intercept (x = 0).
2. Find the x-intercepts (set f(x) = 0, use factor theorem).
3. Find the turning points: set f'(x) = 0 and solve.
4. Determine the nature: use f''(x) or test sign of f'(x) around the point.
5. Sketch the curve.

## Optimisation

1. Set up the function to be maximised or minimised.
2. Differentiate and set f'(x) = 0.
3. Solve for x.
4. Verify it's a max/min using the second derivative or sign change.

**Example:** A farmer has 100 m of fencing for a rectangular camp with one side against a wall.
Let x = width. Then length = 100 - 2x.
Area = x(100 - 2x) = 100x - 2x^2
A'(x) = 100 - 4x = 0 → x = 25
Max area = 25(50) = 1250 m^2`,
      },
    ],
    quiz: {
      title: "Differential Calculus Quiz",
      description: "Differentiation, tangent lines, cubic graphs, and optimisation.",
      difficulty: "hard",
      questions: [
        {
          questionText: "Differentiate: f(x) = 3x^4 - 2x^2 + 5",
          type: "multiple_choice",
          options: ["12x^3 - 4x", "12x^3 - 4x + 5", "3x^3 - 2x", "12x^4 - 4x^2"],
          correctAnswer: "12x^3 - 4x",
          explanation: "Apply power rule: 4(3)x^3 - 2(2)x + 0 = 12x^3 - 4x.",
        },
        {
          questionText: "The gradient of the tangent to f(x) = x^2 at x = 3 is:",
          type: "short_answer",
          correctAnswer: "6",
          explanation: "f'(x) = 2x, f'(3) = 6.",
        },
        {
          questionText: "Turning points occur where:",
          type: "multiple_choice",
          options: ["f'(x) = 0", "f(x) = 0", "f''(x) = 0", "f(x) = f'(x)"],
          correctAnswer: "f'(x) = 0",
          explanation: "Set the first derivative to zero to find turning points.",
        },
        {
          questionText: "If f''(a) < 0, the turning point at x = a is a:",
          type: "multiple_choice",
          options: ["Maximum", "Minimum", "Point of inflection", "Saddle point"],
          correctAnswer: "Maximum",
          explanation: "Negative second derivative means concave down = local maximum.",
        },
        {
          questionText: "In optimisation, after differentiating we set f'(x) = ___ to find critical values.",
          type: "short_answer",
          correctAnswer: "0",
          explanation: "Critical values occur where f'(x) = 0.",
        },
      ],
    },
  },

  {
    key: "math12-analytical-geometry-circles",
    title: "Analytical Geometry: Circles",
    description:
      "Equation of a circle, tangent to a circle, and intersection of lines and circles.",
    grade: 12,
    order: 7,
    capsTags: [
      "circles",
      "equation of a circle",
      "tangent to a circle",
      "analytical geometry",
    ],
    lessons: [
      {
        title: "Equation of a Circle",
        type: "text",
        order: 1,
        content: `# Equation of a Circle

## Standard Form
(x - a)^2 + (y - b)^2 = r^2

Centre: (a, b), Radius: r

## General Form
x^2 + y^2 + Dx + Ey + F = 0

To convert to standard form: complete the square for x and y.

**Example:** x^2 + y^2 - 6x + 4y - 12 = 0
(x^2 - 6x + 9) + (y^2 + 4y + 4) = 12 + 9 + 4
(x - 3)^2 + (y + 2)^2 = 25
Centre: (3, -2), Radius: 5

## Finding the Equation
Given centre and radius, substitute directly.
Given centre and a point on the circle, find r using the distance formula.
Given three points, substitute each into the general form to get three equations.`,
      },
      {
        title: "Tangent to a Circle",
        type: "text",
        order: 2,
        content: `# Tangent to a Circle

## Key Property
A tangent is perpendicular to the radius at the point of tangency.

## Finding the Tangent Equation
1. Find the gradient of the radius from centre to the point of tangency.
2. The tangent gradient = -1 / (radius gradient).
3. Use point-gradient form with the point of tangency.

**Example:** Circle (x-2)^2 + (y-3)^2 = 25, tangent at point (5, 7).
Radius gradient: (7-3)/(5-2) = 4/3
Tangent gradient: -3/4
Equation: y - 7 = -3/4 (x - 5)

## Length of Tangent from External Point
If P is external and C is the centre:
Length = sqrt(PC^2 - r^2)

## Intersection of Line and Circle
Substitute the line equation into the circle equation.
- 2 solutions: line is a secant (two intersection points)
- 1 solution (discriminant = 0): line is a tangent
- No solution: line does not intersect the circle`,
      },
    ],
    quiz: {
      title: "Analytical Geometry: Circles Quiz",
      description: "Circle equations, tangents, and intersections.",
      difficulty: "hard",
      questions: [
        {
          questionText: "The standard form of a circle with centre (2, -3) and radius 4 is:",
          type: "multiple_choice",
          options: [
            "(x-2)^2 + (y+3)^2 = 16",
            "(x+2)^2 + (y-3)^2 = 16",
            "(x-2)^2 + (y-3)^2 = 4",
            "(x-2)^2 + (y+3)^2 = 4",
          ],
          correctAnswer: "(x-2)^2 + (y+3)^2 = 16",
          explanation: "Centre (2,-3) means (x-2)^2 + (y-(-3))^2 = 4^2.",
        },
        {
          questionText: "A tangent to a circle is ___ to the radius at the point of tangency.",
          type: "short_answer",
          correctAnswer: "Perpendicular",
          explanation: "Fundamental property: tangent ⊥ radius.",
        },
        {
          questionText: "If a line intersects a circle at exactly one point, the discriminant equals:",
          type: "multiple_choice",
          options: ["0", "Positive", "Negative", "1"],
          correctAnswer: "0",
          explanation: "One solution means discriminant = 0 (tangent).",
        },
        {
          questionText: "Convert x^2 + y^2 - 4x + 2y - 4 = 0 to standard form. The centre is:",
          type: "short_answer",
          correctAnswer: "(2, -1)",
          explanation: "(x-2)^2 + (y+1)^2 = 4 + 1 + 4 = 9. Centre (2, -1).",
        },
        {
          questionText: "To find where a line meets a circle, you ___ the line into the circle equation.",
          type: "multiple_choice",
          options: ["Substitute", "Differentiate", "Integrate", "Factor"],
          correctAnswer: "Substitute",
          explanation: "Substitute y = mx + c into the circle equation and solve.",
        },
      ],
    },
  },

  {
    key: "math12-euclidean-geometry",
    title: "Euclidean Geometry: Proportionality and Similarity",
    description:
      "Proportionality theorem, similar triangles, and proof of the Pythagorean theorem.",
    grade: 12,
    order: 8,
    capsTags: [
      "proportionality",
      "similar triangles",
      "euclidean geometry",
      "mid-point theorem",
    ],
    lessons: [
      {
        title: "Proportionality Theorems",
        type: "text",
        order: 1,
        content: `# Proportionality

## Proportionality Theorem
A line drawn parallel to one side of a triangle divides the other two sides proportionally.

If DE || BC in triangle ABC:
AD/DB = AE/EC

## Converse
If a line divides two sides of a triangle proportionally, it is parallel to the third side.

## Mid-point Theorem
The line joining the midpoints of two sides of a triangle is parallel to the third side and half its length.

## Applications
- Prove lines are parallel by showing proportional division.
- Calculate unknown lengths using the proportionality ratios.`,
      },
      {
        title: "Similar Triangles",
        type: "text",
        order: 2,
        content: `# Similar Triangles

## Conditions for Similarity
Two triangles are similar if:
1. All corresponding angles are equal (AAA), or
2. All corresponding sides are in proportion (SSS similarity), or
3. Two sides are in proportion and the included angle is equal (SAS similarity).

## Properties
If triangle ABC ||| triangle DEF:
- AB/DE = BC/EF = AC/DF
- The ratio of their areas = (ratio of sides)^2

## Proving Similarity
1. Identify the two triangles.
2. Show that the conditions for similarity are met.
3. Write the proportion statement.

## Theorem of Pythagoras (proof using similarity)
In right-angled triangle ABC with the right angle at C and altitude CD to AB:
- Triangle ACD ||| triangle ABC ||| triangle CBD
- AC^2 + BC^2 = AB^2 (follows from the similarity ratios)`,
      },
    ],
    quiz: {
      title: "Euclidean Geometry: Proportionality Quiz",
      description: "Proportionality theorem, similar triangles, and applications.",
      difficulty: "hard",
      questions: [
        {
          questionText: "If DE || BC in triangle ABC, then AD/DB = ___.",
          type: "short_answer",
          correctAnswer: "AE/EC",
          explanation: "Proportionality theorem: parallel line divides sides proportionally.",
        },
        {
          questionText: "Two triangles are similar if all corresponding ___ are equal.",
          type: "multiple_choice",
          options: ["Angles", "Sides", "Altitudes", "Medians"],
          correctAnswer: "Angles",
          explanation: "AAA (angle-angle-angle) proves similarity.",
        },
        {
          questionText: "The mid-point theorem states the line joining midpoints is ___ the third side.",
          type: "multiple_choice",
          options: ["Parallel to and half", "Perpendicular to", "Equal to", "Twice"],
          correctAnswer: "Parallel to and half",
          explanation: "The midpoint line is parallel and half the length of the third side.",
        },
        {
          questionText: "If two similar triangles have sides in ratio 2:3, their areas are in ratio:",
          type: "multiple_choice",
          options: ["4:9", "2:3", "8:27", "1:1"],
          correctAnswer: "4:9",
          explanation: "Area ratio = (side ratio)^2 = 4:9.",
        },
        {
          questionText: "The Pythagorean theorem can be proved using ___ triangles.",
          type: "multiple_choice",
          options: ["Similar", "Congruent", "Isosceles", "Equilateral"],
          correctAnswer: "Similar",
          explanation: "The altitude from the right angle creates similar triangles.",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 4
  // ──────────────────────────────────────────

  {
    key: "math12-statistics-regression",
    title: "Statistics: Regression and Correlation",
    description:
      "Bivariate data, scatter plots, least squares regression line, and correlation coefficient.",
    grade: 12,
    order: 9,
    capsTags: [
      "statistics",
      "regression",
      "correlation",
      "scatter plot",
      "least squares",
    ],
    lessons: [
      {
        title: "Scatter Plots and Correlation",
        type: "text",
        order: 1,
        content: `# Bivariate Statistics

## Scatter Plots
Plot pairs of data (x, y) on a coordinate plane to visualise the relationship.

## Types of Correlation
- **Strong positive:** points cluster closely along an upward line (r close to 1)
- **Weak positive:** upward trend but scattered (r between 0 and 0.5)
- **Strong negative:** points cluster along a downward line (r close to -1)
- **No correlation:** no clear pattern (r close to 0)

## Correlation Coefficient (r)
- -1 <= r <= 1
- |r| close to 1: strong linear relationship
- |r| close to 0: weak or no linear relationship
- Sign of r: positive = positive correlation, negative = negative correlation

## Interpreting r
- |r| > 0.8: strong
- 0.5 < |r| < 0.8: moderate
- |r| < 0.5: weak`,
      },
      {
        title: "Least Squares Regression Line",
        type: "text",
        order: 2,
        content: `# Least Squares Regression Line

## Equation: y = a + bx

The line that minimises the sum of squared residuals.

## Formulas
b = (n . sum(xy) - sum(x) . sum(y)) / (n . sum(x^2) - (sum(x))^2)
a = mean(y) - b . mean(x)

Or use your calculator's regression function.

## The Line Passes Through (mean(x), mean(y))

## Making Predictions
- **Interpolation:** predicting within the data range (reliable)
- **Extrapolation:** predicting outside the data range (less reliable)

## Residuals
Residual = actual y - predicted y
A good model has small, randomly scattered residuals.

## Important Notes
- Correlation does not imply causation.
- Always check the scatter plot for outliers or non-linear patterns before fitting a line.`,
      },
    ],
    quiz: {
      title: "Statistics: Regression Quiz",
      description: "Scatter plots, correlation coefficient, and regression lines.",
      difficulty: "medium",
      questions: [
        {
          questionText: "A correlation coefficient of r = -0.92 indicates:",
          type: "multiple_choice",
          options: [
            "Strong negative correlation",
            "Weak negative correlation",
            "Strong positive correlation",
            "No correlation",
          ],
          correctAnswer: "Strong negative correlation",
          explanation: "|r| = 0.92 is close to 1 (strong), and r is negative.",
        },
        {
          questionText: "The least squares regression line always passes through:",
          type: "multiple_choice",
          options: ["(mean x, mean y)", "The origin", "(0, a)", "(1, b)"],
          correctAnswer: "(mean x, mean y)",
          explanation: "By definition, the regression line passes through the point of means.",
        },
        {
          questionText: "Predicting outside the data range is called:",
          type: "multiple_choice",
          options: ["Extrapolation", "Interpolation", "Regression", "Correlation"],
          correctAnswer: "Extrapolation",
          explanation: "Extrapolation = predicting beyond the observed data range.",
        },
        {
          questionText: "Correlation does NOT imply:",
          type: "short_answer",
          correctAnswer: "Causation",
          explanation: "Two variables can be correlated without one causing the other.",
        },
        {
          questionText: "In y = a + bx, b represents the:",
          type: "multiple_choice",
          options: ["Gradient (slope)", "y-intercept", "Correlation", "Mean"],
          correctAnswer: "Gradient (slope)",
          explanation: "b is the slope of the regression line.",
        },
      ],
    },
  },

  {
    key: "math12-counting-probability",
    title: "Counting Principles and Probability",
    description:
      "Fundamental counting principle, permutations, factorial notation, and probability with counting.",
    grade: 12,
    order: 10,
    capsTags: [
      "counting",
      "permutations",
      "factorial",
      "probability",
      "fundamental counting principle",
    ],
    lessons: [
      {
        title: "Counting Principles",
        type: "text",
        order: 1,
        content: `# Fundamental Counting Principle

If there are m ways to do the first task and n ways to do the second task, there are m x n ways to do both.

**Example:** 3 shirts and 4 pants → 3 x 4 = 12 outfits.

## Factorial Notation
n! = n x (n-1) x (n-2) x ... x 2 x 1
0! = 1

**Example:** 5! = 120

## Permutations (order matters)
The number of ways to arrange n objects is n!

## Permutations with Repetition
If there are repeated elements:
n! / (p! x q! x ...)

**Example:** Arrangements of BOOK:
4! / 2! = 12 (two O's repeat)

## Restrictions
Handle restrictions first, then arrange the remaining items.

**Example:** 5 people in a row, but A must be first:
Fix A in position 1, arrange remaining 4: 4! = 24`,
      },
      {
        title: "Probability Using Counting",
        type: "text",
        order: 2,
        content: `# Probability with Counting

## Formula
P(event) = number of favourable outcomes / total number of outcomes

Use counting techniques to calculate both numerator and denominator.

**Example:** A 4-digit code using digits 1-9 (no repetition). What is the probability the code is even?
Total codes: 9 x 8 x 7 x 6 = 3024
Even codes: last digit must be 2, 4, 6, or 8 (4 choices)
Remaining 3 positions: 8 x 7 x 6 = 336
Even codes: 4 x 336 = 1344
P(even) = 1344/3024 = 4/9

## Common Patterns
- "At least one" → use complement: P(at least 1) = 1 - P(none)
- Seating arrangements: circular = (n-1)!
- Selecting a committee (order doesn't matter): use combinations: C(n,r) = n! / (r!(n-r)!)`,
      },
    ],
    quiz: {
      title: "Counting Principles Quiz",
      description: "Factorial, permutations, counting principle, and probability.",
      difficulty: "medium",
      questions: [
        {
          questionText: "What is 6!?",
          type: "short_answer",
          correctAnswer: "720",
          explanation: "6! = 6 x 5 x 4 x 3 x 2 x 1 = 720.",
        },
        {
          questionText: "How many ways can 5 books be arranged on a shelf?",
          type: "multiple_choice",
          options: ["120", "25", "60", "24"],
          correctAnswer: "120",
          explanation: "5! = 120.",
        },
        {
          questionText: "How many arrangements of the letters in MATHS?",
          type: "short_answer",
          correctAnswer: "120",
          explanation: "5 distinct letters: 5! = 120.",
        },
        {
          questionText: "0! equals:",
          type: "multiple_choice",
          options: ["1", "0", "Undefined", "Infinity"],
          correctAnswer: "1",
          explanation: "By definition, 0! = 1.",
        },
        {
          questionText: "The fundamental counting principle multiplies the number of ___ for each task.",
          type: "multiple_choice",
          options: ["Choices", "Probabilities", "Factorials", "Permutations"],
          correctAnswer: "Choices",
          explanation: "Multiply the number of choices at each stage.",
        },
      ],
    },
  },
];
