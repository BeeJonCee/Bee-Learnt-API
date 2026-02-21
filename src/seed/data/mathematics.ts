import type { ModuleSeed, SubjectSeed } from "../types.js";
import { grade11Modules } from "./mathematics-grade11.js";
import { grade12Modules } from "./mathematics-grade12.js";

export const subject: SubjectSeed = {
  name: "Mathematics",
  description:
    "CAPS-aligned mathematics covering Grades 10-12: algebra, functions, trigonometry, calculus, finance, statistics, geometry, and probability.",
  minGrade: 10,
  maxGrade: 12,
};

export const modules: ModuleSeed[] = [
  // ──────────────────────────────────────────
  // TERM 1
  // ──────────────────────────────────────────

  {
    key: "math-algebraic-expressions",
    title: "Algebraic Expressions",
    description:
      "Products and factors, simplification of algebraic expressions, and factorisation techniques including common factor, difference of squares, trinomials, and grouping.",
    grade: 10,
    order: 1,
    capsTags: [
      "algebraic expressions",
      "factorisation",
      "products",
      "common factor",
      "difference of squares",
      "trinomials",
      "grouping",
    ],
    lessons: [
      {
        title: "Products and Simplification of Algebraic Expressions",
        type: "text",
        order: 1,
        content: `# Products and Simplification

## Multiplying Algebraic Expressions

When multiplying algebraic expressions we apply the **distributive property** and collect like terms.

### Monomial x Binomial

a(b + c) = ab + ac

**Example:** 3x(2x - 5) = 6x^2 - 15x

### Binomial x Binomial (FOIL)

(a + b)(c + d) = ac + ad + bc + bd

**Example:** (2x + 3)(x - 4) = 2x^2 - 8x + 3x - 12 = 2x^2 - 5x - 12

### Squaring a Binomial

(a + b)^2 = a^2 + 2ab + b^2
(a - b)^2 = a^2 - 2ab + b^2

**Example:** (3x + 2)^2 = 9x^2 + 12x + 4

### Product of Sum and Difference

(a + b)(a - b) = a^2 - b^2

**Example:** (5x + 3)(5x - 3) = 25x^2 - 9

## Simplification

To simplify an algebraic expression:
1. Expand all products.
2. Collect like terms (terms with the same variable raised to the same power).
3. Write the answer in descending powers.

**Example:** Simplify (x + 2)(x - 3) + 2x(x + 1)
= x^2 - 3x + 2x - 6 + 2x^2 + 2x
= 3x^2 + x - 6`,
      },
      {
        title: "Factorisation Techniques",
        type: "text",
        order: 2,
        content: `# Factorisation

Factorisation is the reverse of expansion. We write an expression as a product of its factors.

## 1. Highest Common Factor (HCF)

Look for the greatest factor common to every term.

**Example:** 6x^3 + 9x^2 = 3x^2(2x + 3)

## 2. Difference of Two Squares

a^2 - b^2 = (a + b)(a - b)

**Example:** 4x^2 - 25 = (2x + 5)(2x - 5)

## 3. Trinomials of the Form x^2 + bx + c

Find two numbers that multiply to c and add to b.

**Example:** x^2 + 7x + 12 = (x + 3)(x + 4)   because 3 x 4 = 12 and 3 + 4 = 7

## 4. Trinomials of the Form ax^2 + bx + c (a not equal to 1)

Use grouping or trial and error.

**Example:** 2x^2 + 7x + 3
Find two numbers that multiply to 2 x 3 = 6 and add to 7: those are 6 and 1.
= 2x^2 + 6x + x + 3
= 2x(x + 3) + 1(x + 3)
= (2x + 1)(x + 3)

## 5. Factorisation by Grouping

Group terms in pairs and factor each pair, then extract the common binomial.

**Example:** x^3 + x^2 + 2x + 2
= x^2(x + 1) + 2(x + 1)
= (x^2 + 2)(x + 1)

## Always check your answer by expanding the factored form.`,
      },
      {
        title: "Algebraic Fractions",
        type: "text",
        order: 3,
        content: `# Simplification of Algebraic Fractions

## Simplifying a Single Fraction

1. Factorise the numerator and denominator completely.
2. Cancel common factors.

**Example:** (x^2 - 9) / (x^2 + 5x + 6)
= (x + 3)(x - 3) / ((x + 2)(x + 3))
= (x - 3) / (x + 2),  where x is not equal to -3

## Adding and Subtracting Algebraic Fractions

1. Find the Lowest Common Denominator (LCD).
2. Rewrite each fraction with the LCD.
3. Add or subtract the numerators.
4. Simplify if possible.

**Example:** 3/(x + 1) + 2/(x - 1)
LCD = (x + 1)(x - 1)
= 3(x - 1)/((x + 1)(x - 1)) + 2(x + 1)/((x + 1)(x - 1))
= (3x - 3 + 2x + 2) / ((x + 1)(x - 1))
= (5x - 1) / (x^2 - 1)

## Multiplying and Dividing Algebraic Fractions

- Multiply: factorise, cancel, then multiply numerators and denominators.
- Divide: invert the second fraction and multiply.`,
      },
    ],
    quiz: {
      title: "Algebraic Expressions Quiz",
      description:
        "Products, factorisation, and simplification of algebraic expressions.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Expand and simplify: (2x + 3)(x - 4)",
          type: "short_answer",
          correctAnswer: "2x^2 - 5x - 12",
          explanation:
            "Using FOIL: 2x^2 - 8x + 3x - 12 = 2x^2 - 5x - 12.",
        },
        {
          questionText: "Factorise completely: 6x^2 + 9x",
          type: "short_answer",
          correctAnswer: "3x(2x + 3)",
          explanation: "The HCF of 6x^2 and 9x is 3x.",
        },
        {
          questionText: "Factorise: x^2 - 16",
          type: "multiple_choice",
          options: [
            "(x + 4)(x - 4)",
            "(x + 8)(x - 2)",
            "(x - 4)^2",
            "(x + 16)(x - 1)",
          ],
          correctAnswer: "(x + 4)(x - 4)",
          explanation:
            "This is a difference of two squares: x^2 - 4^2 = (x + 4)(x - 4).",
        },
        {
          questionText: "Factorise: x^2 + 5x + 6",
          type: "short_answer",
          correctAnswer: "(x + 2)(x + 3)",
          explanation:
            "Find two numbers that multiply to 6 and add to 5: 2 and 3.",
        },
        {
          questionText: "Expand: (3x - 2)^2",
          type: "short_answer",
          correctAnswer: "9x^2 - 12x + 4",
          explanation:
            "Using (a - b)^2 = a^2 - 2ab + b^2: 9x^2 - 12x + 4.",
        },
        {
          questionText:
            "Explain why x^2 + 9 cannot be factorised as a difference of two squares over the real numbers.",
          type: "essay",
          correctAnswer:
            "The difference of two squares requires a subtraction (a^2 - b^2). Since x^2 + 9 is a sum, it does not fit the pattern and cannot be factorised using real numbers.",
          explanation:
            "a^2 - b^2 = (a + b)(a - b) requires a minus sign between the squares.",
        },
      ],
    },
  },

  {
    key: "math-exponents",
    title: "Exponents",
    description:
      "Laws of exponents, simplification using exponent rules, rational exponents, and solving exponential equations.",
    grade: 10,
    order: 2,
    capsTags: [
      "exponents",
      "exponent laws",
      "rational exponents",
      "exponential equations",
    ],
    lessons: [
      {
        title: "Laws of Exponents",
        type: "text",
        order: 1,
        content: `# Laws of Exponents

For a, b not equal to 0 and m, n integers:

## The Seven Laws

| Law | Rule |
|-----|------|
| Product rule | a^m * a^n = a^(m+n) |
| Quotient rule | a^m / a^n = a^(m-n) |
| Power of a power | (a^m)^n = a^(m*n) |
| Power of a product | (ab)^n = a^n * b^n |
| Power of a quotient | (a/b)^n = a^n / b^n |
| Zero exponent | a^0 = 1 |
| Negative exponent | a^(-n) = 1/a^n |

## Examples

1. 2^3 * 2^4 = 2^7 = 128
2. x^5 / x^2 = x^3
3. (3^2)^3 = 3^6 = 729
4. (2x)^3 = 8x^3
5. 5^(-2) = 1/25

## Prime Factorisation

Express numbers as products of primes before applying laws.

**Example:** Simplify 12^2 * 3^(-1)
= (2^2 * 3)^2 * 3^(-1)
= 2^4 * 3^2 * 3^(-1)
= 16 * 3
= 48`,
      },
      {
        title: "Rational Exponents and Simplification",
        type: "text",
        order: 2,
        content: `# Rational Exponents

A rational exponent is a fraction: a^(m/n) = n-th root of (a^m).

## Key Definitions

- a^(1/2) = square root of a
- a^(1/3) = cube root of a
- a^(m/n) = (n-th root of a)^m = n-th root of (a^m)

## Examples

1. 8^(1/3) = cube root of 8 = 2
2. 16^(3/4) = (4th root of 16)^3 = 2^3 = 8
3. 27^(2/3) = (cube root of 27)^2 = 3^2 = 9

## Simplification Strategy

When simplifying expressions with exponents:
1. Convert roots to rational exponents.
2. Express all bases as prime factors.
3. Apply the exponent laws.
4. Simplify and give answers with positive exponents.

**Example:** Simplify (2^3 * 4^2) / 8^2
= (2^3 * (2^2)^2) / (2^3)^2
= (2^3 * 2^4) / 2^6
= 2^7 / 2^6
= 2^1
= 2`,
      },
      {
        title: "Exponential Equations",
        type: "text",
        order: 3,
        content: `# Solving Exponential Equations

An exponential equation has the variable in the exponent.

## Strategy: Equal Bases

If a^x = a^y, then x = y (for a > 0, a not equal to 1).

### Steps
1. Express both sides with the same base.
2. Set the exponents equal.
3. Solve the resulting equation.

## Examples

**Example 1:** Solve 2^x = 16
2^x = 2^4, so x = 4

**Example 2:** Solve 3^(x+1) = 27
3^(x+1) = 3^3, so x + 1 = 3, therefore x = 2

**Example 3:** Solve 5^(2x) = 1/25
5^(2x) = 5^(-2), so 2x = -2, therefore x = -1

**Example 4:** Solve 4^x = 8
(2^2)^x = 2^3
2^(2x) = 2^3
2x = 3, therefore x = 3/2

## Special Cases

- a^x = 1 means x = 0 (for any base a not equal to 0)
- a^x = a means x = 1`,
      },
    ],
    quiz: {
      title: "Exponents Quiz",
      description: "Laws of exponents, rational exponents, and exponential equations.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Simplify: 2a^2 * 3a^3",
          type: "short_answer",
          correctAnswer: "6a^5",
          explanation:
            "Multiply coefficients (2 * 3 = 6) and add exponents (2 + 3 = 5).",
        },
        {
          questionText: "What is 5^0?",
          type: "multiple_choice",
          options: ["0", "1", "5", "25"],
          correctAnswer: "1",
          explanation: "Any non-zero number raised to the power 0 equals 1.",
        },
        {
          questionText: "Simplify: (3^2)^4",
          type: "short_answer",
          correctAnswer: "3^8",
          explanation: "Power of a power: multiply exponents, so 2 * 4 = 8.",
        },
        {
          questionText: "Evaluate: 8^(2/3)",
          type: "short_answer",
          correctAnswer: "4",
          explanation:
            "8^(1/3) = 2 (cube root of 8), then 2^2 = 4.",
        },
        {
          questionText: "Solve for x: 2^(x+1) = 32",
          type: "short_answer",
          correctAnswer: "4",
          explanation:
            "32 = 2^5, so x + 1 = 5, therefore x = 4.",
        },
        {
          questionText:
            "Explain why a negative exponent produces a fraction.",
          type: "essay",
          correctAnswer:
            "A negative exponent means the reciprocal: a^(-n) = 1/a^n. This follows from the quotient rule: a^0 / a^n = a^(0-n) = a^(-n), and since a^0 = 1, we get 1/a^n.",
          explanation:
            "The negative exponent law is derived from the quotient rule of exponents.",
        },
      ],
    },
  },

  {
    key: "math-equations-inequalities",
    title: "Equations and Inequalities",
    description:
      "Linear equations, quadratic equations by factoring, simultaneous equations in two unknowns, literal equations (changing the subject), and linear inequalities with number line representation.",
    grade: 10,
    order: 3,
    capsTags: [
      "linear equations",
      "quadratic equations",
      "simultaneous equations",
      "literal equations",
      "inequalities",
    ],
    lessons: [
      {
        title: "Linear and Quadratic Equations",
        type: "text",
        order: 1,
        content: `# Solving Equations

## Linear Equations

A linear equation has the variable to the first power. The goal is to isolate the variable.

**Example:** Solve 3x - 7 = 2x + 5
3x - 2x = 5 + 7
x = 12

**With fractions:** Solve x/3 + 2 = x/2 - 1
Multiply by LCD (6): 2x + 12 = 3x - 6
12 + 6 = 3x - 2x
x = 18

## Quadratic Equations (by Factoring)

A quadratic equation has the form ax^2 + bx + c = 0.

### Steps:
1. Write the equation in standard form (= 0).
2. Factorise the expression.
3. Set each factor equal to zero.
4. Solve for x.

**Example 1:** Solve x^2 - 5x + 6 = 0
(x - 2)(x - 3) = 0
x = 2 or x = 3

**Example 2:** Solve 2x^2 + 3x = 0
x(2x + 3) = 0
x = 0 or x = -3/2

**Example 3:** Solve x^2 = 9
x^2 - 9 = 0
(x + 3)(x - 3) = 0
x = -3 or x = 3`,
      },
      {
        title: "Simultaneous Equations and Literal Equations",
        type: "text",
        order: 2,
        content: `# Simultaneous Equations

Two equations with two unknowns are solved together. At Grade 10 level both equations are linear.

## Method 1: Substitution

1. Solve one equation for one variable.
2. Substitute into the other equation.
3. Solve, then back-substitute.

**Example:** Solve y = 2x + 1 and 3x + y = 11
Substitute: 3x + (2x + 1) = 11
5x + 1 = 11
5x = 10
x = 2, so y = 2(2) + 1 = 5

## Method 2: Elimination

1. Multiply equations to match a coefficient.
2. Add or subtract to eliminate one variable.

**Example:** Solve 2x + 3y = 12 and x - 3y = -3
Add the equations: 3x = 9, so x = 3.
Substitute: 2(3) + 3y = 12, so 3y = 6, y = 2.

# Literal Equations (Changing the Subject)

Rearrange a formula to make a different variable the subject.

**Example 1:** Make r the subject of A = pi * r^2
r^2 = A / pi
r = sqrt(A / pi)   (r > 0)

**Example 2:** Make t the subject of v = u + at
v - u = at
t = (v - u) / a`,
      },
      {
        title: "Linear Inequalities",
        type: "text",
        order: 3,
        content: `# Linear Inequalities

A linear inequality uses <, >, <=, or >= instead of =.

## Solving Rules

- Add or subtract the same value on both sides (sign unchanged).
- Multiply or divide by a **positive** number (sign unchanged).
- Multiply or divide by a **negative** number: **reverse the inequality sign**.

**Example 1:** Solve 2x + 3 > 7
2x > 4
x > 2

**Example 2:** Solve -3x + 6 <= 12
-3x <= 6
x >= -2   (sign reversed because we divided by -3)

## Number Line Representation

- Use an **open circle** (or hollow dot) for < or > (value not included).
- Use a **closed circle** (or filled dot) for <= or >= (value included).
- Shade the line in the direction of all valid values.

**Example:** x > 2 is shown with an open circle at 2 and shading to the right.
x <= -1 is shown with a closed circle at -1 and shading to the left.

## Interval Notation

- x > 2: (2; infinity)
- x <= -1: (-infinity; -1]
- -3 < x <= 5: (-3; 5]

## Double Inequalities

**Example:** Solve -1 < 2x + 3 <= 9
Subtract 3: -4 < 2x <= 6
Divide by 2: -2 < x <= 3`,
      },
    ],
    quiz: {
      title: "Equations and Inequalities Quiz",
      description:
        "Linear equations, quadratic equations, simultaneous equations, and inequalities.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Solve: 3x - 7 = 2x + 5",
          type: "short_answer",
          correctAnswer: "x = 12",
          explanation: "3x - 2x = 5 + 7, so x = 12.",
        },
        {
          questionText: "Solve: x^2 - 5x + 6 = 0",
          type: "short_answer",
          correctAnswer: "x = 2 or x = 3",
          explanation:
            "Factorise: (x - 2)(x - 3) = 0, so x = 2 or x = 3.",
        },
        {
          questionText:
            "Solve the simultaneous equations: y = 2x + 1 and 3x + y = 11",
          type: "short_answer",
          correctAnswer: "x = 2, y = 5",
          explanation:
            "Substitute y = 2x + 1 into the second equation: 3x + 2x + 1 = 11, so 5x = 10, x = 2, y = 5.",
        },
        {
          questionText: "Solve the inequality: -3x + 6 <= 12",
          type: "multiple_choice",
          options: ["x >= -2", "x <= -2", "x >= 2", "x <= 6"],
          correctAnswer: "x >= -2",
          explanation:
            "-3x <= 6; dividing by -3 reverses the sign, giving x >= -2.",
        },
        {
          questionText:
            "Make h the subject of the formula V = (1/3) * pi * r^2 * h",
          type: "short_answer",
          correctAnswer: "h = 3V / (pi * r^2)",
          explanation:
            "Multiply both sides by 3: 3V = pi * r^2 * h. Then divide by (pi * r^2).",
        },
        {
          questionText:
            "Explain why you must reverse the inequality sign when dividing both sides by a negative number.",
          type: "essay",
          correctAnswer:
            "Multiplying or dividing by a negative number changes the order of numbers on the number line. For example, 2 < 3, but -2 > -3. This reversal of order means the inequality direction must also reverse to remain true.",
          explanation:
            "Negative multiplication reverses the order relationship between numbers.",
        },
      ],
    },
  },

  {
    key: "math-number-patterns",
    title: "Number Patterns",
    description:
      "Linear sequences, identifying the constant difference, generating terms, and deriving the nth term formula T_n = an + b.",
    grade: 10,
    order: 4,
    capsTags: [
      "number patterns",
      "linear sequences",
      "constant difference",
      "nth term",
    ],
    lessons: [
      {
        title: "Linear Sequences and Constant Difference",
        type: "text",
        order: 1,
        content: `# Number Patterns — Linear Sequences

## What is a Sequence?

A **sequence** is an ordered list of numbers following a rule. Each number is called a **term**.

We label terms: T_1 (first term), T_2 (second term), T_3 (third term), and so on.

## Linear Sequences

A sequence is **linear** if there is a **constant difference** (d) between consecutive terms.

d = T_2 - T_1 = T_3 - T_2 = T_4 - T_3 = ...

### Example 1
Sequence: 4, 7, 10, 13, 16, ...
Differences: 3, 3, 3, 3
d = 3 (constant), so this is a linear sequence.

### Example 2
Sequence: 20, 15, 10, 5, 0, ...
Differences: -5, -5, -5, -5
d = -5 (constant), so this is a linear sequence with a negative difference.

### Example 3
Sequence: 2, 4, 8, 16, ...
Differences: 2, 4, 8
The difference is not constant, so this is NOT a linear sequence.

## Generating Terms

Given the first term (a) and common difference (d), the next terms are:
T_1 = a
T_2 = a + d
T_3 = a + 2d
T_4 = a + 3d`,
      },
      {
        title: "The nth Term Formula",
        type: "text",
        order: 2,
        content: `# Finding the General Term

## The Formula

For a linear sequence with first term a and common difference d:

**T_n = a + (n - 1)d**

This can be rewritten as: T_n = dn + (a - d)

In the form T_n = An + B, where A = d and B = a - d.

## Example 1

Sequence: 4, 7, 10, 13, ...
a = 4, d = 3
T_n = 4 + (n - 1)(3) = 4 + 3n - 3 = 3n + 1

Check: T_1 = 3(1) + 1 = 4. T_2 = 3(2) + 1 = 7. Correct.

## Example 2

Sequence: 20, 15, 10, 5, ...
a = 20, d = -5
T_n = 20 + (n - 1)(-5) = 20 - 5n + 5 = -5n + 25

Check: T_1 = -5(1) + 25 = 20. T_3 = -5(3) + 25 = 10. Correct.

## Finding a Specific Term

**Example:** In the sequence 3, 8, 13, 18, ..., find T_20.
d = 5, a = 3
T_n = 3 + (n - 1)(5) = 5n - 2
T_20 = 5(20) - 2 = 98

## Finding Which Term Has a Given Value

**Example:** Which term of 4, 7, 10, 13, ... equals 61?
T_n = 3n + 1 = 61
3n = 60
n = 20
So T_20 = 61.`,
      },
    ],
    quiz: {
      title: "Number Patterns Quiz",
      description:
        "Constant difference, generating terms, and nth term formula.",
      difficulty: "easy",
      questions: [
        {
          questionText:
            "Find the common difference of the sequence: 4, 7, 10, 13, ...",
          type: "short_answer",
          correctAnswer: "3",
          explanation: "Each term increases by 3: 7 - 4 = 3.",
        },
        {
          questionText:
            "Write the nth term formula for the sequence: 4, 7, 10, 13, ...",
          type: "short_answer",
          correctAnswer: "T_n = 3n + 1",
          explanation:
            "a = 4, d = 3; T_n = 4 + (n-1)(3) = 3n + 1.",
        },
        {
          questionText: "If T_n = 2n + 5, find T_6.",
          type: "short_answer",
          correctAnswer: "17",
          explanation: "T_6 = 2(6) + 5 = 17.",
        },
        {
          questionText: "A linear sequence has:",
          type: "multiple_choice",
          options: [
            "A constant difference between consecutive terms",
            "A constant ratio between consecutive terms",
            "No pattern at all",
            "Only positive terms",
          ],
          correctAnswer: "A constant difference between consecutive terms",
          explanation:
            "Linear sequences are defined by a constant first difference.",
        },
        {
          questionText: "Is the sequence 2, 4, 8, 16 linear? Explain.",
          type: "short_answer",
          correctAnswer:
            "No, it is not linear because the differences (2, 4, 8) are not constant.",
          explanation:
            "The differences between terms are 2, 4, 8 which are not equal.",
        },
        {
          questionText:
            "Which term of the sequence 5, 9, 13, 17, ... is equal to 81?",
          type: "short_answer",
          correctAnswer: "20",
          explanation:
            "T_n = 4n + 1. Set 4n + 1 = 81, so 4n = 80, n = 20.",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 2
  // ──────────────────────────────────────────

  {
    key: "math-functions-graphs",
    title: "Functions: Linear, Quadratic, Hyperbolic, and Exponential",
    description:
      "Function notation, domain and range, linear functions (y = mx + c), quadratic functions (y = ax^2 + q), hyperbolic functions (y = a/x + q), exponential functions (y = ab^x + q), sketching and interpreting graphs, and the effects of parameters a and q.",
    grade: 10,
    order: 5,
    capsTags: [
      "functions",
      "linear function",
      "quadratic function",
      "hyperbola",
      "exponential function",
      "domain",
      "range",
      "graphs",
      "parameters",
    ],
    lessons: [
      {
        title: "Function Notation, Linear and Quadratic Functions",
        type: "text",
        order: 1,
        content: `# Functions — Notation and Linear & Quadratic Types

## What is a Function?

A function is a rule that assigns each input (x) exactly one output (y). We write f(x) to denote the output of function f for input x.

**Domain:** the set of all valid x-values (inputs).
**Range:** the set of all possible y-values (outputs).

## Linear Functions: y = mx + c

**Shape:** a straight line.

| Parameter | Effect |
|-----------|--------|
| m (gradient) | m > 0 line rises left to right; m < 0 line falls left to right; m = 0 horizontal line |
| c (y-intercept) | The point where the line crosses the y-axis: (0, c) |

**Domain:** x is any real number.
**Range:** y is any real number (unless m = 0, then range = {c}).

**Example:** y = 2x - 3
Gradient = 2 (positive slope, rises), y-intercept at (0, -3).
x-intercept: 0 = 2x - 3, so x = 3/2, giving the point (3/2, 0).

## Quadratic Functions: y = ax^2 + q

**Shape:** a parabola with axis of symmetry along the y-axis (x = 0).

| Parameter | Effect |
|-----------|--------|
| a > 0 | Parabola opens upward ("smile") |
| a < 0 | Parabola opens downward ("frown") |
| Larger |a| | Narrower parabola |
| Smaller |a| | Wider parabola |
| q > 0 | Graph shifts q units up |
| q < 0 | Graph shifts q units down |

**Turning point:** (0, q).
**Axis of symmetry:** x = 0.
**Domain:** x is any real number.
**Range:** y >= q (if a > 0) or y <= q (if a < 0).

**Example:** y = 2x^2 - 8
Turning point: (0, -8). Opens up. y-intercept: (0, -8).
x-intercepts: 0 = 2x^2 - 8, so x^2 = 4, x = -2 or x = 2.`,
      },
      {
        title: "Hyperbolic and Exponential Functions",
        type: "text",
        order: 2,
        content: `# Hyperbolic and Exponential Functions

## Hyperbolic Functions: y = a/x + q

**Shape:** two separate curves (a hyperbola) in opposite quadrants.

**Asymptotes:**
- Vertical asymptote: x = 0 (the y-axis)
- Horizontal asymptote: y = q

| Parameter | Effect |
|-----------|--------|
| a > 0 | Curves in quadrants 1 and 3 (above q in Q1, below q in Q3) |
| a < 0 | Curves in quadrants 2 and 4 |
| q | Shifts the graph up (q > 0) or down (q < 0) |

**Domain:** x is any real number except 0.
**Range:** y is any real number except q.

**Example:** y = 4/x + 1
Horizontal asymptote: y = 1. Vertical asymptote: x = 0.
When x = 2: y = 4/2 + 1 = 3. When x = -2: y = 4/(-2) + 1 = -1.

## Exponential Functions: y = ab^x + q

**Shape:** a curve that increases or decreases rapidly.

**Key features:**
- Horizontal asymptote: y = q
- y-intercept: (0, a + q) since b^0 = 1

| Parameter | Effect |
|-----------|--------|
| a > 0 and b > 1 | Increasing (growth) curve above y = q |
| a > 0 and 0 < b < 1 | Decreasing (decay) curve above y = q |
| a < 0 | Reflected below the asymptote y = q |
| q | Shifts the graph up or down |

**Domain:** x is any real number.
**Range:** y > q (if a > 0) or y < q (if a < 0).

**Example:** y = 2^x - 1
Asymptote: y = -1. y-intercept: (0, 2^0 - 1) = (0, 0).
When x = 3: y = 8 - 1 = 7. When x = -1: y = 1/2 - 1 = -1/2.`,
      },
      {
        title: "Sketching Graphs and Interpreting Functions",
        type: "text",
        order: 3,
        content: `# Sketching and Interpreting Graphs

## Steps for Sketching Any Function

1. Identify the **type** of function (linear, quadratic, hyperbolic, exponential).
2. Find the **y-intercept** (set x = 0).
3. Find the **x-intercept(s)** (set y = 0), if applicable.
4. Identify **asymptotes** (for hyperbola and exponential).
5. Identify the **turning point** (for parabola).
6. Determine the **domain and range**.
7. Plot key points and draw a smooth curve.

## Reading Information from Graphs

Given a graph, you should be able to:
- Determine the equation by identifying a, q, m, or c.
- Read off intercepts, turning points, and asymptotes.
- Determine where f(x) > 0, f(x) < 0, f(x) = g(x).

## Determining Equations from Graphs

**Linear:** Identify two points on the line, find gradient m = (y2 - y1)/(x2 - x1), then use y = mx + c.

**Quadratic (y = ax^2 + q):** Read the turning point (0, q) from the graph, then substitute another point to find a.

**Hyperbolic (y = a/x + q):** Read the horizontal asymptote for q, then substitute a known point to find a.

**Exponential (y = ab^x + q):** Read the asymptote for q, then use two points to find a and b.

## Intersections of Graphs

To find where f(x) = g(x), set the equations equal and solve. The solutions give the x-coordinates of the intersection points.`,
      },
    ],
    quiz: {
      title: "Functions and Graphs Quiz",
      description:
        "Linear, quadratic, hyperbolic, and exponential functions with parameter effects.",
      difficulty: "medium",
      questions: [
        {
          questionText: "In y = 3x - 5, identify the gradient and y-intercept.",
          type: "short_answer",
          correctAnswer: "Gradient = 3, y-intercept = -5",
          explanation:
            "In y = mx + c, m = 3 is the gradient and c = -5 is the y-intercept.",
        },
        {
          questionText:
            "What is the turning point of y = -2x^2 + 5?",
          type: "short_answer",
          correctAnswer: "(0, 5)",
          explanation:
            "For y = ax^2 + q, the turning point is (0, q) = (0, 5).",
        },
        {
          questionText:
            "What is the horizontal asymptote of y = 3/x - 2?",
          type: "multiple_choice",
          options: ["y = 0", "y = -2", "y = 3", "y = 2"],
          correctAnswer: "y = -2",
          explanation:
            "For y = a/x + q, the horizontal asymptote is y = q = -2.",
        },
        {
          questionText:
            "For y = 2^x + 3, what is the range?",
          type: "short_answer",
          correctAnswer: "y > 3",
          explanation:
            "The asymptote is y = 3, and a > 0 with b > 1, so the range is y > 3.",
        },
        {
          questionText:
            "If a parabola y = ax^2 + q has a < 0, it opens:",
          type: "multiple_choice",
          options: ["Upward", "Downward", "Left", "Right"],
          correctAnswer: "Downward",
          explanation:
            "When a < 0, the parabola opens downward (frown shape).",
        },
        {
          questionText:
            "Explain the effect of the parameter q on the graph of y = ax^2 + q.",
          type: "essay",
          correctAnswer:
            "The parameter q shifts the entire parabola vertically. If q > 0, the graph shifts up by q units; if q < 0, it shifts down by |q| units. The turning point moves from (0, 0) to (0, q).",
          explanation:
            "q controls the vertical translation of the parabola.",
        },
      ],
    },
  },

  {
    key: "math-finance",
    title: "Finance: Simple and Compound Interest",
    description:
      "Simple interest (A = P(1 + in)), compound interest (A = P(1 + i)^n), hire purchase, inflation, population growth, and currency exchange rates.",
    grade: 10,
    order: 6,
    capsTags: [
      "simple interest",
      "compound interest",
      "hire purchase",
      "inflation",
      "exchange rates",
      "financial mathematics",
    ],
    lessons: [
      {
        title: "Simple Interest",
        type: "text",
        order: 1,
        content: `# Simple Interest

## Formula

**A = P(1 + in)**

Where:
- **A** = accumulated (final) amount
- **P** = principal (initial amount)
- **i** = interest rate per period (as a decimal, e.g. 8% = 0.08)
- **n** = number of time periods (usually years)

The **interest earned** is: I = P * i * n = A - P

## Key Feature

With simple interest, the interest is calculated on the **original principal only**. The interest earned each year is the same.

## Examples

**Example 1:** R5 000 is invested at 8% simple interest per year for 3 years.
A = 5000(1 + 0.08 * 3) = 5000(1.24) = R6 200
Interest earned = R6 200 - R5 000 = R1 200

**Example 2:** Find the time needed for R2 000 to grow to R2 600 at 10% simple interest.
2600 = 2000(1 + 0.10 * n)
1.3 = 1 + 0.1n
0.3 = 0.1n
n = 3 years

## Hire Purchase

Hire purchase is a way of buying goods on credit. Simple interest is charged on the full cash price.

**Example:** A laptop costs R12 000 cash. On hire purchase, a 10% deposit is required and the balance is paid over 2 years at 15% simple interest per year.
Deposit = 10% of R12 000 = R1 200
Balance = R12 000 - R1 200 = R10 800
A = 10 800(1 + 0.15 * 2) = 10 800(1.30) = R14 040
Monthly payment = R14 040 / 24 = R585
Total paid = R1 200 + R14 040 = R15 240`,
      },
      {
        title: "Compound Interest, Inflation, and Exchange Rates",
        type: "text",
        order: 2,
        content: `# Compound Interest

## Formula

**A = P(1 + i)^n**

Where:
- **A** = accumulated amount
- **P** = principal
- **i** = interest rate per compounding period (as a decimal)
- **n** = number of compounding periods

## Key Feature

With compound interest, interest is calculated on the principal **plus previously accumulated interest**. This produces exponential growth.

## Example

R5 000 is invested at 8% compound interest per year for 3 years.
A = 5000(1 + 0.08)^3 = 5000(1.08)^3 = 5000(1.259712) = R6 298.56
Compare with simple interest: R6 200. Compound interest earns R98.56 more.

## Simple vs Compound Interest

| Feature | Simple | Compound |
|---------|--------|----------|
| Interest on | Original amount only | Accumulated amount |
| Growth | Linear | Exponential |
| Formula | A = P(1 + in) | A = P(1 + i)^n |

## Inflation

Inflation uses the compound interest formula to calculate how prices increase over time.

**Example:** A loaf of bread costs R18 now. If inflation averages 6% per year, what will it cost in 5 years?
A = 18(1 + 0.06)^5 = 18(1.3382256) = R24.09

## Population Growth

Population growth also follows the compound formula.

**Example:** A town has 50 000 people. If the population grows at 2.5% per year, what will it be in 10 years?
A = 50000(1.025)^10 = 50000(1.2800845) = 64 004

## Currency Exchange Rates

An exchange rate tells you how much of one currency equals another.

**Example:** If 1 USD = R18.50, how many rand is $250?
R = 250 * 18.50 = R4 625

How many dollars is R10 000?
$ = 10 000 / 18.50 = $540.54`,
      },
    ],
    quiz: {
      title: "Finance Quiz",
      description:
        "Simple interest, compound interest, hire purchase, inflation, and exchange rates.",
      difficulty: "medium",
      questions: [
        {
          questionText:
            "Calculate the simple interest on R1 000 at 10% per year for 2 years.",
          type: "short_answer",
          correctAnswer: "R200",
          explanation: "I = P * i * n = 1000 * 0.10 * 2 = R200.",
        },
        {
          questionText:
            "Find the accumulated amount when R5 000 is invested at 8% compound interest for 3 years.",
          type: "short_answer",
          correctAnswer: "R6 298.56",
          explanation:
            "A = 5000(1.08)^3 = 5000 * 1.259712 = R6 298.56.",
        },
        {
          questionText:
            "A TV costs R8 000 cash. On hire purchase, you pay 10% deposit and the rest over 2 years at 12% simple interest. What is the total amount paid?",
          type: "short_answer",
          correctAnswer: "R9 728",
          explanation:
            "Deposit = R800. Balance = R7 200. Interest on balance = 7200 * 0.12 * 2 = R1 728. Amount on balance = R7 200 + R1 728 = R8 928. Total paid = R800 + R8 928 = R9 728.",
          points: 3,
        },
        {
          questionText:
            "Which formula represents compound interest?",
          type: "multiple_choice",
          options: [
            "A = P(1 + i)^n",
            "A = P(1 + in)",
            "A = P + in",
            "A = P * i * n",
          ],
          correctAnswer: "A = P(1 + i)^n",
          explanation:
            "Compound interest uses the exponential formula A = P(1 + i)^n.",
        },
        {
          questionText:
            "If 1 USD = R18.50, convert R5 550 to US dollars.",
          type: "short_answer",
          correctAnswer: "$300",
          explanation: "5550 / 18.50 = 300.",
        },
        {
          questionText:
            "Explain the difference between simple and compound interest. Why does compound interest yield more over time?",
          type: "essay",
          correctAnswer:
            "Simple interest is calculated only on the original principal, so the interest earned each period is constant. Compound interest is calculated on the principal plus all previously earned interest, so the interest grows each period. Over time, the compounding effect (interest on interest) causes compound interest to exceed simple interest by an increasing margin.",
          explanation:
            "Compound interest earns interest on interest, producing exponential growth.",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 3
  // ──────────────────────────────────────────

  {
    key: "math-analytical-geometry",
    title: "Analytical Geometry",
    description:
      "Distance formula, midpoint formula, gradient of a line, equation of a straight line, parallel and perpendicular lines, and inclination of a line.",
    grade: 10,
    order: 7,
    capsTags: [
      "analytical geometry",
      "distance formula",
      "midpoint",
      "gradient",
      "equation of a line",
      "parallel lines",
      "perpendicular lines",
      "inclination",
    ],
    lessons: [
      {
        title: "Distance, Midpoint, and Gradient",
        type: "text",
        order: 1,
        content: `# Analytical Geometry — Core Formulae

All formulae use two points: A(x_1, y_1) and B(x_2, y_2).

## Distance Formula

The distance between A and B:

**d = sqrt((x_2 - x_1)^2 + (y_2 - y_1)^2)**

**Example:** Distance between (1, 2) and (4, 6):
d = sqrt((4-1)^2 + (6-2)^2) = sqrt(9 + 16) = sqrt(25) = 5

## Midpoint Formula

The midpoint M of segment AB:

**M = ((x_1 + x_2)/2, (y_1 + y_2)/2)**

**Example:** Midpoint of (2, 3) and (8, 7):
M = ((2+8)/2, (3+7)/2) = (5, 5)

## Gradient (Slope) Formula

The gradient m of line AB:

**m = (y_2 - y_1) / (x_2 - x_1)**

**Example:** Gradient between (1, 3) and (5, 11):
m = (11 - 3) / (5 - 1) = 8/4 = 2

### Special Cases
- Horizontal line: m = 0 (y-values are equal)
- Vertical line: m is undefined (x-values are equal)
- Positive gradient: line rises from left to right
- Negative gradient: line falls from left to right`,
      },
      {
        title: "Equation of a Straight Line",
        type: "text",
        order: 2,
        content: `# Equation of a Straight Line

## Forms of the Equation

### Gradient-Intercept Form
**y = mx + c**
where m = gradient and c = y-intercept.

### Two-Point Form
Given points (x_1, y_1) and (x_2, y_2):
**y - y_1 = m(x - x_1)** where m = (y_2 - y_1)/(x_2 - x_1)

## Finding the Equation

**Example 1:** Gradient m = 3, passes through (2, 5).
y - 5 = 3(x - 2)
y = 3x - 6 + 5
y = 3x - 1

**Example 2:** Passes through (1, 4) and (3, 10).
m = (10 - 4)/(3 - 1) = 6/2 = 3
y - 4 = 3(x - 1)
y = 3x + 1

## Horizontal and Vertical Lines
- Horizontal line through (a, b): y = b (gradient = 0)
- Vertical line through (a, b): x = a (gradient undefined)`,
      },
      {
        title: "Parallel, Perpendicular Lines and Inclination",
        type: "text",
        order: 3,
        content: `# Parallel Lines, Perpendicular Lines, and Inclination

## Parallel Lines

Two lines are **parallel** if and only if they have the **same gradient**:
m_1 = m_2

**Example:** y = 2x + 3 and y = 2x - 7 are parallel (both have m = 2).

## Perpendicular Lines

Two lines are **perpendicular** if and only if:
**m_1 * m_2 = -1**

Equivalently: m_2 = -1/m_1

**Example:** y = 2x + 1 and y = -1/2 x + 4 are perpendicular because 2 * (-1/2) = -1.

## Inclination of a Line

The **inclination** (theta) is the angle the line makes with the positive x-axis, measured counter-clockwise.

**tan(theta) = m**

So theta = arctan(m), where 0 <= theta < 180.

### Cases:
- If m > 0: theta is an acute angle (0 < theta < 90)
- If m = 0: theta = 0 (horizontal line)
- If m < 0: theta is obtuse (90 < theta < 180). Calculate using theta = 180 + arctan(m)

**Example:** A line with gradient m = 1.
tan(theta) = 1, so theta = 45.

**Example:** A line with gradient m = -1.
tan(theta) = -1, so theta = 180 - 45 = 135.`,
      },
    ],
    quiz: {
      title: "Analytical Geometry Quiz",
      description:
        "Distance, midpoint, gradient, equations of lines, and inclination.",
      difficulty: "medium",
      questions: [
        {
          questionText: "Find the distance between (1, 2) and (4, 6).",
          type: "short_answer",
          correctAnswer: "5",
          explanation:
            "d = sqrt((4-1)^2 + (6-2)^2) = sqrt(9 + 16) = sqrt(25) = 5.",
        },
        {
          questionText: "Find the midpoint of (3, -1) and (7, 5).",
          type: "short_answer",
          correctAnswer: "(5, 2)",
          explanation:
            "M = ((3+7)/2, (-1+5)/2) = (5, 2).",
        },
        {
          questionText:
            "Find the gradient of the line through (2, 1) and (6, 9).",
          type: "short_answer",
          correctAnswer: "2",
          explanation: "m = (9-1)/(6-2) = 8/4 = 2.",
        },
        {
          questionText:
            "Which pair of gradients indicates perpendicular lines?",
          type: "multiple_choice",
          options: [
            "m = 3 and m = -1/3",
            "m = 3 and m = 3",
            "m = 2 and m = -2",
            "m = 1 and m = 1",
          ],
          correctAnswer: "m = 3 and m = -1/3",
          explanation:
            "Perpendicular lines satisfy m_1 * m_2 = -1. Since 3 * (-1/3) = -1, these are perpendicular.",
        },
        {
          questionText:
            "Find the equation of the line with gradient 2 passing through (1, 3).",
          type: "short_answer",
          correctAnswer: "y = 2x + 1",
          explanation:
            "y - 3 = 2(x - 1), so y = 2x - 2 + 3 = 2x + 1.",
        },
        {
          questionText:
            "If a line has gradient m = 1, what is the inclination angle?",
          type: "short_answer",
          correctAnswer: "45 degrees",
          explanation:
            "tan(theta) = 1, so theta = arctan(1) = 45 degrees.",
        },
      ],
    },
  },

  {
    key: "math-trigonometry",
    title: "Trigonometry",
    description:
      "Trigonometric ratios (sin, cos, tan) in right triangles, reciprocal ratios (cosec, sec, cot), special angles (30, 45, 60 degrees), solving right-angled triangles, trigonometric equations, graphs of sin, cos, tan, and the area rule.",
    grade: 10,
    order: 8,
    capsTags: [
      "trigonometry",
      "sin",
      "cos",
      "tan",
      "special angles",
      "trigonometric equations",
      "trig graphs",
      "area rule",
    ],
    lessons: [
      {
        title: "Trigonometric Ratios and Special Angles",
        type: "text",
        order: 1,
        content: `# Trigonometric Ratios

## Definitions in a Right-Angled Triangle

For an angle theta in a right-angled triangle:

- **sin(theta)** = opposite / hypotenuse
- **cos(theta)** = adjacent / hypotenuse
- **tan(theta)** = opposite / adjacent

Memory aid: **SOH-CAH-TOA**

## Reciprocal Ratios

- **cosec(theta)** = 1/sin(theta) = hypotenuse / opposite
- **sec(theta)** = 1/cos(theta) = hypotenuse / adjacent
- **cot(theta)** = 1/tan(theta) = adjacent / opposite

## Special Angles

| Angle | sin | cos | tan |
|-------|-----|-----|-----|
| 0 | 0 | 1 | 0 |
| 30 | 1/2 | sqrt(3)/2 | 1/sqrt(3) |
| 45 | sqrt(2)/2 | sqrt(2)/2 | 1 |
| 60 | sqrt(3)/2 | 1/2 | sqrt(3) |
| 90 | 1 | 0 | undefined |

These values come from two special triangles:
- The **45-45-90** triangle (isosceles right triangle) with sides 1, 1, sqrt(2).
- The **30-60-90** triangle with sides 1, sqrt(3), 2.

## Example

In a right triangle, the opposite side to theta is 3 and the hypotenuse is 5.
sin(theta) = 3/5 = 0.6
The adjacent side = sqrt(5^2 - 3^2) = sqrt(16) = 4
cos(theta) = 4/5 = 0.8
tan(theta) = 3/4 = 0.75`,
      },
      {
        title: "Solving Triangles and Trigonometric Equations",
        type: "text",
        order: 2,
        content: `# Solving Right-Angled Triangles

## Finding a Side

Given an angle and one side, use the appropriate ratio to find the unknown side.

**Example:** In triangle ABC, angle B = 90, angle A = 35, and BC = 8.
We need AB (adjacent to angle A) and AC (hypotenuse).
tan(35) = BC / AB = 8 / AB
AB = 8 / tan(35) = 8 / 0.7002 = 11.42

## Finding an Angle

Given two sides, use the inverse trig function to find the angle.

**Example:** opposite = 6, adjacent = 8.
tan(theta) = 6/8 = 0.75
theta = arctan(0.75) = 36.87 degrees

## Solving Trigonometric Equations

At Grade 10 level, solve equations for 0 <= theta <= 90 (first quadrant).

**Example 1:** Solve sin(theta) = 0.5
theta = arcsin(0.5) = 30 degrees

**Example 2:** Solve 2cos(theta) - 1 = 0
cos(theta) = 1/2
theta = 60 degrees

**Example 3:** Solve tan(theta) = sqrt(3)
theta = 60 degrees

## The Area Rule

The area of any triangle (not just right-angled) with sides a and b and included angle C:

**Area = (1/2) * a * b * sin(C)**

**Example:** Find the area of a triangle with sides 7 cm and 10 cm and an included angle of 50 degrees.
Area = (1/2)(7)(10)sin(50) = 35 * 0.766 = 26.81 cm^2`,
      },
      {
        title: "Graphs of Trigonometric Functions",
        type: "text",
        order: 3,
        content: `# Graphs of Trigonometric Functions

## y = sin(x)

- **Shape:** smooth wave oscillating between -1 and 1
- **Period:** 360 degrees (one full cycle)
- **Amplitude:** 1
- **Key points:** sin(0) = 0, sin(90) = 1, sin(180) = 0, sin(270) = -1, sin(360) = 0
- **Domain:** all real numbers
- **Range:** -1 <= y <= 1

## y = cos(x)

- **Shape:** smooth wave oscillating between -1 and 1
- **Period:** 360 degrees
- **Amplitude:** 1
- **Key points:** cos(0) = 1, cos(90) = 0, cos(180) = -1, cos(270) = 0, cos(360) = 1
- **Relationship:** cos(x) = sin(x + 90) — the cosine graph is the sine graph shifted 90 degrees to the left

## y = tan(x)

- **Shape:** repeating curve with vertical asymptotes
- **Period:** 180 degrees
- **Asymptotes:** at x = 90, x = 270, etc. (where cos(x) = 0)
- **Key points:** tan(0) = 0, tan(45) = 1, tan(135) = -1, tan(180) = 0
- **Range:** all real numbers

## Effects of Parameters

For y = a * sin(x) + q:
- |a| changes the **amplitude** (vertical stretch)
- q shifts the graph **vertically**

For y = sin(bx):
- b changes the **period** to 360/b degrees

**Example:** y = 2sin(x) - 1 has amplitude 2, shifted down 1 unit. Range: -3 <= y <= 1.`,
      },
    ],
    quiz: {
      title: "Trigonometry Quiz",
      description:
        "Trig ratios, special angles, solving triangles, and trig graphs.",
      difficulty: "medium",
      questions: [
        {
          questionText:
            "If the opposite side is 3 and the hypotenuse is 5, what is sin(theta)?",
          type: "short_answer",
          correctAnswer: "3/5",
          explanation: "sin(theta) = opposite / hypotenuse = 3/5.",
        },
        {
          questionText: "What is cos(60)?",
          type: "multiple_choice",
          options: ["0", "1/2", "sqrt(3)/2", "1"],
          correctAnswer: "1/2",
          explanation:
            "From the special angles table, cos(60) = 1/2.",
        },
        {
          questionText: "Solve for theta (0 <= theta <= 90): sin(theta) = 0.5",
          type: "short_answer",
          correctAnswer: "30 degrees",
          explanation: "theta = arcsin(0.5) = 30 degrees.",
        },
        {
          questionText:
            "Find the area of a triangle with sides 8 cm and 12 cm and included angle 30 degrees.",
          type: "short_answer",
          correctAnswer: "24 cm^2",
          explanation:
            "Area = (1/2)(8)(12)sin(30) = (1/2)(8)(12)(1/2) = 24 cm^2.",
        },
        {
          questionText: "The period of y = tan(x) is:",
          type: "multiple_choice",
          options: [
            "180 degrees",
            "360 degrees",
            "90 degrees",
            "270 degrees",
          ],
          correctAnswer: "180 degrees",
          explanation: "The tangent function repeats every 180 degrees.",
        },
        {
          questionText:
            "Explain the relationship between the sine and cosine graphs.",
          type: "essay",
          correctAnswer:
            "The cosine graph is identical in shape to the sine graph but shifted 90 degrees to the left. This means cos(x) = sin(x + 90). Both have the same period (360 degrees), amplitude (1), and range ([-1, 1]), but they start at different points: sin(0) = 0 while cos(0) = 1.",
          explanation:
            "cos(x) = sin(x + 90): the cosine graph leads the sine graph by 90 degrees.",
        },
      ],
    },
  },

  {
    key: "math-euclidean-geometry",
    title: "Euclidean Geometry",
    description:
      "Properties of triangles (scalene, isosceles, equilateral, right-angled), properties of quadrilaterals (parallelogram, rectangle, rhombus, square, trapezium, kite), congruence (SSS, SAS, ASA, RHS), similarity, and the midpoint theorem.",
    grade: 10,
    order: 9,
    capsTags: [
      "euclidean geometry",
      "triangles",
      "quadrilaterals",
      "congruence",
      "similarity",
      "midpoint theorem",
    ],
    lessons: [
      {
        title: "Properties of Triangles and Congruence",
        type: "text",
        order: 1,
        content: `# Properties of Triangles

## Types of Triangles

| Type | Properties |
|------|-----------|
| **Scalene** | All sides different, all angles different |
| **Isosceles** | Two sides equal, base angles equal |
| **Equilateral** | All sides equal, all angles = 60 degrees |
| **Right-angled** | One angle = 90 degrees |

## Key Triangle Properties

- The sum of the interior angles of a triangle = 180 degrees.
- The exterior angle of a triangle = the sum of the two non-adjacent interior angles.
- The longest side is opposite the largest angle.
- The triangle inequality: the sum of any two sides > the third side.

## Congruence of Triangles

Two triangles are **congruent** if they are identical in shape and size (all corresponding sides and angles are equal).

### Conditions for Congruence

| Condition | Meaning |
|-----------|---------|
| **SSS** | Three sides of one triangle equal three sides of the other |
| **SAS** | Two sides and the included angle are equal |
| **ASA** (or AAS) | Two angles and a corresponding side are equal |
| **RHS** | Right angle, hypotenuse, and one other side are equal |

**Example:** In triangles ABC and DEF, if AB = DE, angle A = angle D, and AC = DF, then triangle ABC is congruent to triangle DEF (SAS).

## Writing Congruence Proofs

1. State the two triangles being compared.
2. List the matching sides/angles with reasons.
3. State the congruence condition (SSS, SAS, ASA, or RHS).
4. Conclude with the congruence statement (vertices in matching order).`,
      },
      {
        title: "Properties of Quadrilaterals",
        type: "text",
        order: 2,
        content: `# Properties of Quadrilaterals

## Summary of Properties

### Parallelogram
- Opposite sides are parallel and equal.
- Opposite angles are equal.
- Diagonals bisect each other.
- Consecutive angles are supplementary (add to 180 degrees).

### Rectangle
- All properties of a parallelogram.
- All angles are 90 degrees.
- Diagonals are equal in length.

### Rhombus
- All properties of a parallelogram.
- All four sides are equal.
- Diagonals bisect each other at right angles (90 degrees).
- Diagonals bisect the vertex angles.

### Square
- All properties of a rectangle AND a rhombus.
- All sides equal, all angles 90 degrees.
- Diagonals are equal, bisect each other at right angles, and bisect the vertex angles.

### Trapezium
- Exactly one pair of opposite sides is parallel.
- An isosceles trapezium has equal non-parallel sides and equal base angles.

### Kite
- Two pairs of adjacent sides are equal.
- One pair of opposite angles (between unequal sides) are equal.
- Diagonals are perpendicular.
- The longer diagonal bisects the shorter diagonal and bisects the vertex angles at its endpoints.

## Hierarchy

Square is a special rectangle is a special parallelogram.
Square is a special rhombus is a special parallelogram.`,
      },
      {
        title: "Similarity and the Midpoint Theorem",
        type: "text",
        order: 3,
        content: `# Similarity

## What is Similarity?

Two figures are **similar** if they have the same shape but not necessarily the same size.

For triangles, similarity means:
- All corresponding angles are equal.
- All corresponding sides are in the same ratio (proportional).

### Conditions for Similarity of Triangles

| Condition | Meaning |
|-----------|---------|
| **AAA** (or AA) | All three angles of one triangle equal all three of the other |
| **SSS (proportional)** | All three pairs of corresponding sides are in the same ratio |
| **SAS (proportional)** | Two pairs of sides in the same ratio and the included angles equal |

**Example:** If triangle ABC has angles 50, 60, 70 and triangle DEF has angles 50, 60, 70, then triangle ABC is similar to triangle DEF (AAA).

If the ratio of corresponding sides is k, then:
- Corresponding sides: side_DEF = k * side_ABC
- Areas: area_DEF = k^2 * area_ABC

# The Midpoint Theorem

**Statement:** The line segment joining the midpoints of two sides of a triangle is parallel to the third side and equal to half its length.

If D is the midpoint of AB and E is the midpoint of AC, then:
- DE is parallel to BC
- DE = (1/2) * BC

**Converse:** If a line is drawn through the midpoint of one side of a triangle, parallel to another side, it bisects the third side.

**Example:** In triangle ABC, D is the midpoint of AB and E is the midpoint of AC. If BC = 12 cm, then DE = 6 cm and DE is parallel to BC.`,
      },
    ],
    quiz: {
      title: "Euclidean Geometry Quiz",
      description:
        "Triangles, quadrilaterals, congruence, similarity, and the midpoint theorem.",
      difficulty: "medium",
      questions: [
        {
          questionText: "The sum of the interior angles of a triangle is:",
          type: "multiple_choice",
          options: [
            "180 degrees",
            "360 degrees",
            "90 degrees",
            "270 degrees",
          ],
          correctAnswer: "180 degrees",
          explanation:
            "The angle sum property of a triangle states the three interior angles add to 180 degrees.",
        },
        {
          questionText:
            "Which congruence condition requires a right angle, the hypotenuse, and one other side?",
          type: "short_answer",
          correctAnswer: "RHS",
          explanation:
            "RHS stands for Right angle, Hypotenuse, Side.",
        },
        {
          questionText:
            "Name three properties of a parallelogram.",
          type: "essay",
          correctAnswer:
            "1) Opposite sides are parallel and equal. 2) Opposite angles are equal. 3) Diagonals bisect each other. Additional: consecutive angles are supplementary.",
          explanation:
            "A parallelogram has parallel equal opposite sides, equal opposite angles, and bisecting diagonals.",
        },
        {
          questionText:
            "In a rhombus, the diagonals intersect at:",
          type: "multiple_choice",
          options: [
            "Right angles (90 degrees)",
            "45 degrees",
            "60 degrees",
            "Any angle",
          ],
          correctAnswer: "Right angles (90 degrees)",
          explanation:
            "The diagonals of a rhombus bisect each other at right angles.",
        },
        {
          questionText:
            "In triangle PQR, M is the midpoint of PQ and N is the midpoint of PR. If QR = 16 cm, what is MN?",
          type: "short_answer",
          correctAnswer: "8 cm",
          explanation:
            "By the midpoint theorem, MN = (1/2) * QR = (1/2)(16) = 8 cm.",
        },
        {
          questionText:
            "Two triangles have corresponding angles of 40, 60, and 80 degrees. Are they similar or congruent?",
          type: "short_answer",
          correctAnswer:
            "They are similar (by AAA), but not necessarily congruent because we do not know if corresponding sides are equal.",
          explanation:
            "Equal angles guarantee similarity (same shape) but not congruence (same size).",
        },
      ],
    },
  },

  // ──────────────────────────────────────────
  // TERM 4
  // ──────────────────────────────────────────

  {
    key: "math-measurement",
    title: "Measurement",
    description:
      "Perimeter and area of 2D shapes, surface area and volume of 3D objects (prisms, cylinders, cones, pyramids, spheres), conversion of units, and the effect of scaling on area and volume.",
    grade: 10,
    order: 10,
    capsTags: [
      "measurement",
      "perimeter",
      "area",
      "surface area",
      "volume",
      "prisms",
      "cylinders",
      "cones",
      "pyramids",
      "spheres",
      "scaling",
    ],
    lessons: [
      {
        title: "Perimeter and Area of 2D Shapes",
        type: "text",
        order: 1,
        content: `# Perimeter and Area of 2D Shapes

## Perimeter

The perimeter is the total distance around the outside of a shape.

| Shape | Perimeter Formula |
|-------|------------------|
| Square (side s) | P = 4s |
| Rectangle (l x w) | P = 2(l + w) |
| Triangle (sides a, b, c) | P = a + b + c |
| Circle (radius r) | Circumference C = 2 * pi * r |

## Area

| Shape | Area Formula |
|-------|-------------|
| Square | A = s^2 |
| Rectangle | A = l * w |
| Triangle | A = (1/2) * base * height |
| Parallelogram | A = base * height |
| Trapezium | A = (1/2)(a + b) * h, where a and b are parallel sides |
| Rhombus | A = (1/2) * d_1 * d_2, where d_1, d_2 are diagonals |
| Kite | A = (1/2) * d_1 * d_2 |
| Circle | A = pi * r^2 |

## Examples

**Rectangle:** length = 8 m, width = 5 m.
P = 2(8 + 5) = 26 m. A = 8 * 5 = 40 m^2.

**Triangle:** base = 10 cm, height = 6 cm.
A = (1/2)(10)(6) = 30 cm^2.

**Circle:** radius = 7 cm.
C = 2 * pi * 7 = 14pi = 43.98 cm. A = pi * 49 = 153.94 cm^2.`,
      },
      {
        title: "Surface Area and Volume of 3D Objects",
        type: "text",
        order: 2,
        content: `# Surface Area and Volume of 3D Objects

## Formulae

| Object | Surface Area | Volume |
|--------|-------------|--------|
| Rectangular prism (l, w, h) | SA = 2(lw + lh + wh) | V = l * w * h |
| Cube (side s) | SA = 6s^2 | V = s^3 |
| Cylinder (r, h) | SA = 2 * pi * r^2 + 2 * pi * r * h | V = pi * r^2 * h |
| Cone (r, h, slant l) | SA = pi * r^2 + pi * r * l | V = (1/3) * pi * r^2 * h |
| Square pyramid (base s, slant l, h) | SA = s^2 + 2 * s * l | V = (1/3) * s^2 * h |
| Sphere (r) | SA = 4 * pi * r^2 | V = (4/3) * pi * r^3 |

Note: For cones and pyramids, the slant height l and the perpendicular height h are different. They are related by:
l = sqrt(r^2 + h^2) for a cone.

## Examples

**Cylinder:** r = 3 cm, h = 10 cm.
V = pi(3)^2(10) = 90pi = 282.74 cm^3.
SA = 2pi(9) + 2pi(3)(10) = 18pi + 60pi = 78pi = 245.04 cm^2.

**Sphere:** r = 5 cm.
V = (4/3)pi(5)^3 = (4/3)pi(125) = (500/3)pi = 523.60 cm^3.
SA = 4pi(25) = 100pi = 314.16 cm^2.

**Cone:** r = 4 cm, h = 3 cm, l = sqrt(16 + 9) = 5 cm.
V = (1/3)pi(16)(3) = 16pi = 50.27 cm^3.
SA = pi(16) + pi(4)(5) = 16pi + 20pi = 36pi = 113.10 cm^2.`,
      },
      {
        title: "Unit Conversions and the Effect of Scaling",
        type: "text",
        order: 3,
        content: `# Unit Conversions and Scaling

## Unit Conversions

### Length
1 km = 1 000 m
1 m = 100 cm
1 cm = 10 mm

### Area (square the linear factor)
1 m^2 = 10 000 cm^2 (100^2)
1 cm^2 = 100 mm^2 (10^2)
1 km^2 = 1 000 000 m^2 (1000^2)

### Volume (cube the linear factor)
1 m^3 = 1 000 000 cm^3 (100^3)
1 cm^3 = 1 000 mm^3 (10^3)
1 litre = 1 000 cm^3 = 1 000 ml
1 m^3 = 1 000 litres

## Effect of Scaling

When all dimensions of an object are multiplied by a scale factor k:

| Measurement | Factor |
|-------------|--------|
| Length | Multiplied by k |
| Area (surface area) | Multiplied by k^2 |
| Volume | Multiplied by k^3 |

### Example

A cube has side 2 cm. If all dimensions are doubled (k = 2):
- Original: V = 8 cm^3, SA = 24 cm^2
- Scaled: side = 4 cm, V = 64 cm^3 = 8 * 8 (k^3 = 8 times), SA = 96 cm^2 = 4 * 24 (k^2 = 4 times)

### Practical Application

A model of a building is built at a scale of 1:50.
- If the model is 30 cm tall, the real building is 30 * 50 = 1 500 cm = 15 m tall.
- If the model floor area is 200 cm^2, the real floor area is 200 * 50^2 = 500 000 cm^2 = 50 m^2.
- If the model volume is 6 000 cm^3, the real volume is 6 000 * 50^3 = 750 000 000 cm^3 = 750 m^3.`,
      },
    ],
    quiz: {
      title: "Measurement Quiz",
      description:
        "Perimeter, area, surface area, volume, and the effect of scaling.",
      difficulty: "medium",
      questions: [
        {
          questionText:
            "Find the area of a triangle with base 10 cm and height 6 cm.",
          type: "short_answer",
          correctAnswer: "30 cm^2",
          explanation: "A = (1/2)(10)(6) = 30 cm^2.",
        },
        {
          questionText:
            "Find the volume of a cylinder with radius 3 cm and height 10 cm. Give your answer in terms of pi.",
          type: "short_answer",
          correctAnswer: "90pi cm^3",
          explanation: "V = pi * r^2 * h = pi(9)(10) = 90pi cm^3.",
        },
        {
          questionText:
            "If all dimensions of a shape are tripled (k = 3), the volume is multiplied by:",
          type: "multiple_choice",
          options: ["3", "9", "27", "6"],
          correctAnswer: "27",
          explanation:
            "Volume scales by k^3. If k = 3, then k^3 = 27.",
        },
        {
          questionText:
            "Convert 2.5 m^2 to cm^2.",
          type: "short_answer",
          correctAnswer: "25 000 cm^2",
          explanation:
            "1 m^2 = 10 000 cm^2, so 2.5 * 10 000 = 25 000 cm^2.",
        },
        {
          questionText:
            "Find the surface area of a sphere with radius 5 cm. Give your answer in terms of pi.",
          type: "short_answer",
          correctAnswer: "100pi cm^2",
          explanation: "SA = 4 * pi * r^2 = 4 * pi * 25 = 100pi cm^2.",
        },
        {
          questionText:
            "A rectangular prism has dimensions 4 cm by 3 cm by 2 cm. Find its volume and surface area.",
          type: "short_answer",
          correctAnswer: "Volume = 24 cm^3, Surface area = 52 cm^2",
          explanation:
            "V = 4*3*2 = 24. SA = 2(12 + 8 + 6) = 2(26) = 52 cm^2.",
        },
      ],
    },
  },

  {
    key: "math-statistics",
    title: "Statistics",
    description:
      "Measures of central tendency (mean, median, mode), measures of dispersion (range, quartiles, IQR, percentiles), five-number summary, box-and-whisker plots, ogives (cumulative frequency curves), histograms, and frequency polygons.",
    grade: 10,
    order: 11,
    capsTags: [
      "statistics",
      "mean",
      "median",
      "mode",
      "range",
      "quartiles",
      "IQR",
      "box-and-whisker",
      "ogive",
      "histogram",
      "frequency polygon",
    ],
    lessons: [
      {
        title: "Measures of Central Tendency and Dispersion",
        type: "text",
        order: 1,
        content: `# Measures of Central Tendency

## Mean

The **mean** (average) is the sum of all values divided by the number of values.

Mean = (sum of all values) / (number of values)

**Example:** Data: 4, 6, 8, 12. Mean = (4 + 6 + 8 + 12) / 4 = 30/4 = 7.5

### Estimated Mean for Grouped Data
For grouped data, use class midpoints:
Estimated mean = sum(frequency * midpoint) / sum(frequency)

## Median

The **median** is the middle value when data is arranged in order.
- Odd number of values: the middle one.
- Even number of values: the average of the two middle values.

**Example:** Data: 3, 5, 9, 11, 15. Median = 9 (third of five values).
Data: 2, 4, 6, 8. Median = (4 + 6)/2 = 5.

## Mode

The **mode** is the value that occurs most frequently. A data set can have no mode, one mode, or multiple modes.

**Example:** Data: 2, 4, 4, 6, 7. Mode = 4.

# Measures of Dispersion

## Range
Range = maximum value - minimum value

## Quartiles
- **Q1** (lower quartile): median of the lower half of the data (25th percentile)
- **Q2** (median): the middle value (50th percentile)
- **Q3** (upper quartile): median of the upper half (75th percentile)

## Interquartile Range (IQR)
IQR = Q3 - Q1

The IQR contains the middle 50% of the data and is not affected by outliers.

## Percentiles
The p-th percentile is the value below which p% of the data falls.`,
      },
      {
        title: "Five-Number Summary and Box-and-Whisker Plots",
        type: "text",
        order: 2,
        content: `# Five-Number Summary

The five-number summary consists of:
1. **Minimum** value
2. **Q1** (lower quartile)
3. **Q2** (median)
4. **Q3** (upper quartile)
5. **Maximum** value

**Example:** Data (ordered): 2, 3, 5, 7, 8, 10, 12, 14, 16
- Minimum = 2
- Q1 = (3 + 5)/2 = 4  (median of lower half: 2, 3, 5, 7)
- Q2 = 8 (median)
- Q3 = (12 + 14)/2 = 13  (median of upper half: 10, 12, 14, 16)
- Maximum = 16

## Box-and-Whisker Plot

A box-and-whisker plot is a diagram that displays the five-number summary.

How to draw:
1. Draw a number line.
2. Mark the minimum and maximum with vertical lines connected by "whiskers."
3. Draw a box from Q1 to Q3.
4. Draw a vertical line inside the box at the median (Q2).

### Reading a Box-and-Whisker Plot
- The box shows the middle 50% of the data (IQR).
- The left whisker represents the bottom 25%.
- The right whisker represents the top 25%.
- If the median is not centred in the box, the data is skewed.

### Identifying Outliers
An outlier is a value more than 1.5 * IQR below Q1 or above Q3.
Lower fence = Q1 - 1.5 * IQR
Upper fence = Q3 + 1.5 * IQR`,
      },
      {
        title: "Histograms, Frequency Polygons, and Ogives",
        type: "text",
        order: 3,
        content: `# Histograms, Frequency Polygons, and Ogives

## Histograms

A histogram displays the frequency of grouped (continuous) data using bars.

**Key features:**
- The x-axis shows class intervals (e.g. 0-10, 10-20, 20-30).
- The y-axis shows frequency.
- Bars are adjacent (no gaps) because the data is continuous.
- The height of each bar represents the frequency of that interval.

## Frequency Polygons

A frequency polygon is formed by connecting the midpoints of the tops of histogram bars with straight lines.

**Steps:**
1. Calculate the midpoint of each class interval.
2. Plot (midpoint, frequency) for each class.
3. Connect the points with straight lines.
4. Close the polygon by connecting to the x-axis at both ends (using the midpoints of the intervals before the first and after the last class).

## Ogives (Cumulative Frequency Curves)

An ogive shows the **cumulative frequency** (running total) plotted against the upper boundary of each class interval.

**Steps to draw an ogive:**
1. Create a cumulative frequency table.
2. Plot points at (upper class boundary, cumulative frequency).
3. Start at the lower boundary of the first class with cumulative frequency 0.
4. Connect the points with a smooth curve.

**Reading from an ogive:**
- The median is at the 50th percentile (n/2 on the y-axis).
- Q1 is at the 25th percentile (n/4).
- Q3 is at the 75th percentile (3n/4).
- Read across from the y-axis to the curve, then down to the x-axis.`,
      },
    ],
    quiz: {
      title: "Statistics Quiz",
      description:
        "Central tendency, dispersion, box-and-whisker plots, histograms, and ogives.",
      difficulty: "easy",
      questions: [
        {
          questionText: "Find the mean of 4, 6, 8, 12.",
          type: "short_answer",
          correctAnswer: "7.5",
          explanation: "Sum = 30, divided by 4 values = 7.5.",
        },
        {
          questionText: "Find the median of 3, 5, 9, 11, 15.",
          type: "short_answer",
          correctAnswer: "9",
          explanation: "The middle value of the ordered data is 9.",
        },
        {
          questionText:
            "The five-number summary consists of: minimum, Q1, median, Q3, and:",
          type: "multiple_choice",
          options: ["Maximum", "Mean", "Mode", "Range"],
          correctAnswer: "Maximum",
          explanation:
            "The five-number summary is: min, Q1, Q2 (median), Q3, max.",
        },
        {
          questionText:
            "If Q1 = 20 and Q3 = 50, what is the interquartile range (IQR)?",
          type: "short_answer",
          correctAnswer: "30",
          explanation: "IQR = Q3 - Q1 = 50 - 20 = 30.",
        },
        {
          questionText:
            "In a histogram, the bars have no gaps because:",
          type: "multiple_choice",
          options: [
            "The data is continuous",
            "The data is discrete",
            "It looks nicer",
            "The intervals overlap",
          ],
          correctAnswer: "The data is continuous",
          explanation:
            "Histograms display continuous data, so class intervals are adjacent with no gaps.",
        },
        {
          questionText:
            "Explain how to read the median from an ogive.",
          type: "essay",
          correctAnswer:
            "On the ogive, find n/2 on the cumulative frequency (y) axis. Draw a horizontal line from this point to the curve. Then drop a vertical line down to the x-axis. The value where it meets the x-axis is the median.",
          explanation:
            "The median is at the 50th percentile on the cumulative frequency curve.",
        },
      ],
    },
  },

  {
    key: "math-probability",
    title: "Probability",
    description:
      "Theoretical probability, relative frequency, Venn diagrams, mutually exclusive events, complementary events, the addition rule P(A or B) = P(A) + P(B) - P(A and B), tree diagrams, and contingency tables.",
    grade: 10,
    order: 12,
    capsTags: [
      "probability",
      "Venn diagrams",
      "mutually exclusive",
      "complementary events",
      "addition rule",
      "tree diagrams",
      "contingency tables",
    ],
    lessons: [
      {
        title: "Theoretical Probability and Key Concepts",
        type: "text",
        order: 1,
        content: `# Probability

## Basic Definitions

- **Experiment:** an action with uncertain outcomes (e.g. rolling a die).
- **Sample space (S):** the set of all possible outcomes.
- **Event (A):** a subset of the sample space.
- **n(S):** the number of outcomes in the sample space.
- **n(A):** the number of outcomes in event A.

## Theoretical Probability

**P(A) = n(A) / n(S)**

Probability always satisfies: 0 <= P(A) <= 1
- P(A) = 0 means the event is impossible.
- P(A) = 1 means the event is certain.

**Example:** Rolling a fair die. S = {1, 2, 3, 4, 5, 6}, n(S) = 6.
P(rolling a 3) = 1/6.
P(rolling an even number) = 3/6 = 1/2.

## Relative Frequency

Relative frequency = (number of times event occurred) / (total number of trials)

As the number of trials increases, relative frequency approaches theoretical probability. This is the **Law of Large Numbers**.

## Complementary Events

The complement of event A (written A') consists of all outcomes NOT in A.
**P(A') = 1 - P(A)**

**Example:** P(not rolling a 6) = 1 - 1/6 = 5/6.`,
      },
      {
        title: "Venn Diagrams, Mutually Exclusive Events, and the Addition Rule",
        type: "text",
        order: 2,
        content: `# Venn Diagrams and Set Operations

## Venn Diagrams

A Venn diagram uses circles inside a rectangle to show relationships between events.
- The rectangle represents the sample space S.
- Each circle represents an event.
- Overlapping regions show outcomes in both events.

## Set Operations

- **A and B** (intersection): outcomes in BOTH A and B.
- **A or B** (union): outcomes in A OR B or both.
- **A'** (complement): outcomes NOT in A.

## Mutually Exclusive Events

Events A and B are **mutually exclusive** if they cannot happen at the same time.
- P(A and B) = 0
- Their Venn diagram circles do not overlap.

**Example:** Rolling a die: A = {1, 2}, B = {5, 6}. A and B are mutually exclusive.

## The Addition Rule

For ANY two events:
**P(A or B) = P(A) + P(B) - P(A and B)**

For **mutually exclusive** events (P(A and B) = 0):
**P(A or B) = P(A) + P(B)**

## Example with Venn Diagram

In a class of 40 learners: 25 play soccer (S), 18 play cricket (C), and 10 play both.
- n(S only) = 25 - 10 = 15
- n(C only) = 18 - 10 = 8
- n(S and C) = 10
- n(neither) = 40 - 15 - 10 - 8 = 7

P(S or C) = P(S) + P(C) - P(S and C) = 25/40 + 18/40 - 10/40 = 33/40`,
      },
      {
        title: "Tree Diagrams and Contingency Tables",
        type: "text",
        order: 3,
        content: `# Tree Diagrams

A tree diagram shows all possible outcomes of sequential events using branches.

## How to Draw
1. Draw branches for each outcome of the first event.
2. From each branch, draw branches for each outcome of the second event.
3. Write probabilities on each branch.
4. Multiply along branches to find the probability of each combined outcome.

## Example

A bag has 3 red and 2 blue balls. Two balls are drawn one at a time WITHOUT replacement.

First draw: P(R) = 3/5, P(B) = 2/5
Second draw (after R): P(R) = 2/4, P(B) = 2/4
Second draw (after B): P(R) = 3/4, P(B) = 1/4

Outcomes:
- P(R, R) = 3/5 * 2/4 = 6/20 = 3/10
- P(R, B) = 3/5 * 2/4 = 6/20 = 3/10
- P(B, R) = 2/5 * 3/4 = 6/20 = 3/10
- P(B, B) = 2/5 * 1/4 = 2/20 = 1/10

Check: 3/10 + 3/10 + 3/10 + 1/10 = 10/10 = 1. Correct.

# Contingency Tables (Two-Way Tables)

A contingency table organises data about two categorical variables into rows and columns.

## Example

| | Left-handed | Right-handed | Total |
|---|---|---|---|
| Male | 8 | 42 | 50 |
| Female | 12 | 38 | 50 |
| Total | 20 | 80 | 100 |

P(Left-handed) = 20/100 = 1/5
P(Female and Left-handed) = 12/100 = 3/25
P(Male or Left-handed) = P(Male) + P(Left) - P(Male and Left) = 50/100 + 20/100 - 8/100 = 62/100 = 31/50`,
      },
    ],
    quiz: {
      title: "Probability Quiz",
      description:
        "Theoretical probability, Venn diagrams, addition rule, tree diagrams, and contingency tables.",
      difficulty: "medium",
      questions: [
        {
          questionText:
            "A fair die is rolled. What is the probability of rolling an even number?",
          type: "short_answer",
          correctAnswer: "1/2",
          explanation:
            "Even numbers: {2, 4, 6}. P = 3/6 = 1/2.",
        },
        {
          questionText:
            "If P(A) = 0.6, what is P(A')?",
          type: "short_answer",
          correctAnswer: "0.4",
          explanation:
            "P(A') = 1 - P(A) = 1 - 0.6 = 0.4.",
        },
        {
          questionText:
            "Events A and B are mutually exclusive. P(A) = 0.3 and P(B) = 0.5. Find P(A or B).",
          type: "short_answer",
          correctAnswer: "0.8",
          explanation:
            "For mutually exclusive events: P(A or B) = P(A) + P(B) = 0.3 + 0.5 = 0.8.",
        },
        {
          questionText:
            "In a class of 30, 18 play tennis and 15 play netball. 8 play both. How many play neither?",
          type: "multiple_choice",
          options: ["5", "7", "3", "10"],
          correctAnswer: "5",
          explanation:
            "Tennis only = 10, both = 8, netball only = 7. Total playing = 25. Neither = 30 - 25 = 5.",
        },
        {
          questionText:
            "State the addition rule for probability and when it simplifies.",
          type: "essay",
          correctAnswer:
            "The addition rule states: P(A or B) = P(A) + P(B) - P(A and B). When events A and B are mutually exclusive (they cannot both occur), P(A and B) = 0, so the rule simplifies to P(A or B) = P(A) + P(B).",
          explanation:
            "We subtract P(A and B) to avoid double-counting outcomes in the overlap.",
        },
        {
          questionText:
            "A bag contains 4 red and 6 blue balls. One ball is drawn at random. What is P(red)?",
          type: "short_answer",
          correctAnswer: "2/5",
          explanation:
            "Total = 10 balls. P(red) = 4/10 = 2/5.",
        },
      ],
    },
  },
];

// Combined export of all Math modules across all grades
export const allModules: ModuleSeed[] = [
  ...modules,
  ...grade11Modules,
  ...grade12Modules,
];
