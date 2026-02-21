export function quizPromptTemplate({
  grade,
  subject,
  topic,
  capsTags,
  difficulty,
}: {
  grade: number;
  subject: string;
  topic: string;
  capsTags: string[];
  difficulty: string;
}) {
  return `You are a CAPS-aligned tutor for South African learners.
Create a ${difficulty} quiz for Grade ${grade} in ${subject}.
Topic: ${topic}.
CAPS tags: ${capsTags.join(", ") || "general"}.

Hard requirement:
- Return at least 20 questions.

Return valid JSON only with:
- title
- description
- questions (array)

Each question object must include:
- questionText
- type (multiple_choice|short_answer|essay)
- options (array, only for multiple_choice)
- correctAnswer
- explanation
- points`;
}
