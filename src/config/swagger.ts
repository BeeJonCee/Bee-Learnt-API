import "./patch-yaml.js"; // Must be first — patches yaml before swagger-jsdoc loads it
import swaggerJsdoc from "swagger-jsdoc";
import { env } from "./env.js";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "BeeLearnt API",
      version: "1.0.0",
      description:
        "API documentation for BeeLearnt - An educational platform for students and tutors",
      contact: {
        name: "BeeLearnt Support",
        email: "support@beelearnt.com",
      },
    },
    servers: [
      {
        url: "http://localhost:4000",
        description: "Development Server",
      },
      {
        url: "https://bee-learnt-api.onrender.com",
        description: "Production Server",
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
      schemas: {
        ErrorResponse: {
          type: "object",
          properties: {
            message: { type: "string" },
            code: { type: "string" },
          },
        },
        RegisterRequest: {
          type: "object",
          required: ["name", "email", "password"],
          properties: {
            name: { type: "string", example: "Jane Tutor" },
            email: { type: "string", format: "email", example: "jane@beelearnt.com" },
            password: { type: "string", format: "password", minLength: 8 },
            role: {
              type: "string",
              enum: ["STUDENT", "PARENT", "TUTOR", "ADMIN"],
              example: "STUDENT",
            },
          },
        },
        LoginRequest: {
          type: "object",
          required: ["email", "password"],
          properties: {
            email: { type: "string", format: "email", example: "jane@beelearnt.com" },
            password: { type: "string", format: "password", example: "SuperSecure123" },
          },
        },
        AuthResponse: {
          type: "object",
          properties: {
            token: { type: "string", example: "eyJhbGciOi..." },
            user: {
              type: "object",
              properties: {
                id: { type: "string" },
                name: { type: "string" },
                email: { type: "string" },
                role: {
                  type: "string",
                  enum: ["STUDENT", "PARENT", "TUTOR", "ADMIN"],
                },
              },
            },
          },
        },
        Module: {
          type: "object",
          properties: {
            id: { type: "integer", example: 101 },
            title: { type: "string", example: "Algebra Foundations" },
            description: {
              type: "string",
              example: "Interactive lessons covering linear equations and inequalities.",
            },
            subjectId: { type: "integer", example: 5 },
            grade: { type: "string", example: "Grade 10" },
            createdAt: { type: "string", format: "date-time" },
            updatedAt: { type: "string", format: "date-time" },
          },
        },
        ModuleCreateRequest: {
          type: "object",
          required: ["title", "description", "subjectId", "grade"],
          properties: {
            title: { type: "string", example: "Algebra Foundations" },
            description: {
              type: "string",
              example: "Interactive lessons covering linear equations and inequalities.",
            },
            subjectId: { type: "integer", example: 5 },
            grade: { type: "string", example: "Grade 10" },
          },
        },
        ModuleUpdateRequest: {
          type: "object",
          properties: {
            title: { type: "string" },
            description: { type: "string" },
            subjectId: { type: "integer" },
            grade: { type: "string" },
          },
        },
        Lesson: {
          type: "object",
          properties: {
            id: { type: "integer", example: 501 },
            moduleId: { type: "integer", example: 101 },
            title: { type: "string", example: "Linear Equations" },
            durationMinutes: { type: "integer", example: 45 },
            content: { type: "string", example: "<p>Lesson HTML content...</p>" },
            createdAt: { type: "string", format: "date-time" },
            updatedAt: { type: "string", format: "date-time" },
          },
        },
        LessonCreateRequest: {
          type: "object",
          required: ["moduleId", "title", "content"],
          properties: {
            moduleId: { type: "integer", example: 101 },
            title: { type: "string", example: "Linear Equations" },
            content: { type: "string", example: "<p>Lesson HTML content...</p>" },
            durationMinutes: { type: "integer", example: 45 },
          },
        },
        LessonUpdateRequest: {
          type: "object",
          properties: {
            title: { type: "string" },
            content: { type: "string" },
            durationMinutes: { type: "integer" },
          },
        },
        StudentGoal: {
          type: "object",
          properties: {
            id: { type: "string", example: "goal_123" },
            title: { type: "string", example: "Study algebra 5 hours weekly" },
            description: {
              type: "string",
              example: "Complete algebra practice sets before exams",
            },
            targetHours: { type: "number", example: 20 },
            currentHours: { type: "number", example: 8 },
            deadline: { type: "string", format: "date-time" },
            priority: {
              type: "string",
              enum: ["low", "medium", "high"],
              example: "high",
            },
            status: {
              type: "string",
              enum: ["active", "completed", "overdue"],
              example: "active",
            },
            createdAt: { type: "string", format: "date-time" },
            updatedAt: { type: "string", format: "date-time" },
          },
        },
        StudentGoalCreateRequest: {
          type: "object",
          required: ["title", "targetHours", "deadline", "priority"],
          properties: {
            title: { type: "string" },
            description: { type: "string" },
            targetHours: { type: "number" },
            deadline: { type: "string", format: "date-time" },
            priority: {
              type: "string",
              enum: ["low", "medium", "high"],
            },
          },
        },
        StudentGoalUpdateRequest: {
          type: "object",
          properties: {
            title: { type: "string" },
            description: { type: "string" },
            targetHours: { type: "number" },
            currentHours: { type: "number" },
            deadline: { type: "string", format: "date-time" },
            priority: {
              type: "string",
              enum: ["low", "medium", "high"],
            },
            status: {
              type: "string",
              enum: ["active", "completed", "overdue"],
            },
          },
        },
        StudentGoalProgressUpdateRequest: {
          type: "object",
          required: ["hoursSpent"],
          properties: {
            hoursSpent: { type: "number", example: 2 },
          },
        },
        StudentPerformance: {
          type: "object",
          properties: {
            overallScore: { type: "number", example: 87.5 },
            attendancePercentage: { type: "number", example: 91.2 },
            averageAssignmentScore: { type: "number", example: 84.3 },
            strengths: {
              type: "array",
              items: { type: "string" },
            },
            focusAreas: {
              type: "array",
              items: { type: "string" },
            },
            subjectBreakdown: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  subjectId: { type: "integer", example: 12 },
                  subjectName: { type: "string", example: "Mathematics" },
                  averageScore: { type: "number", example: 88 },
                  progress: { type: "number", example: 72 },
                },
              },
            },
          },
        },
        StudentSubjectPerformance: {
          type: "object",
          properties: {
            subjectId: { type: "integer", example: 12 },
            subjectName: { type: "string", example: "Mathematics" },
            trend: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  period: { type: "string", example: "2024-W05" },
                  score: { type: "number", example: 85 },
                },
              },
            },
            upcomingAssessments: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "string", example: "assess_42" },
                  title: { type: "string", example: "Unit 3 Quiz" },
                  dueDate: { type: "string", format: "date-time" },
                },
              },
            },
          },
        },
        StudentLearningPathMilestone: {
          type: "object",
          properties: {
            id: { type: "string", example: "mile_1" },
            title: { type: "string" },
            description: { type: "string" },
            status: {
              type: "string",
              enum: ["not_started", "in_progress", "completed"],
            },
            estimatedHours: { type: "number" },
            actualHours: { type: "number" },
            modules: { type: "integer" },
            lessons: { type: "integer" },
            completedDate: { type: "string", format: "date-time" },
          },
        },
        StudentLearningPath: {
          type: "object",
          properties: {
            id: { type: "string", example: "path_1" },
            name: { type: "string" },
            description: { type: "string" },
            subject: { type: "string" },
            grade: { type: "string" },
            difficulty: {
              type: "string",
              enum: ["beginner", "intermediate", "advanced"],
            },
            totalHours: { type: "number" },
            completedHours: { type: "number" },
            progress: { type: "number" },
            enrolledDate: { type: "string", format: "date-time" },
            estimatedCompletion: { type: "string", format: "date-time" },
            certificateAvailable: { type: "boolean" },
            milestones: {
              type: "array",
              items: { $ref: "#/components/schemas/StudentLearningPathMilestone" },
            },
            skillsGained: {
              type: "array",
              items: { type: "string" },
            },
          },
        },
        StudentLearningPathsResponse: {
          type: "object",
          properties: {
            active: {
              type: "array",
              items: { $ref: "#/components/schemas/StudentLearningPath" },
            },
            completed: {
              type: "array",
              items: { $ref: "#/components/schemas/StudentLearningPath" },
            },
            recommended: {
              type: "array",
              items: { $ref: "#/components/schemas/StudentLearningPath" },
            },
            progressOverTime: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  date: { type: "string", example: "2024-01-01" },
                  hoursCompleted: { type: "number" },
                  pathsActive: { type: "number" },
                },
              },
            },
          },
        },
        StudentResource: {
          type: "object",
          properties: {
            id: { type: "string", example: "res_1" },
            title: { type: "string" },
            description: { type: "string" },
            type: {
              type: "string",
              enum: ["video", "article", "interactive", "textbook"],
            },
            subject: { type: "string" },
            topic: { type: "string" },
            url: { type: "string", format: "uri" },
            difficulty: {
              type: "string",
              enum: ["beginner", "intermediate", "advanced"],
            },
            duration: { type: "number" },
            rating: { type: "number" },
            reviews: { type: "number" },
            relevanceScore: { type: "number" },
            saved: { type: "boolean" },
          },
        },
        StudentRecommendedResourcesResponse: {
          type: "object",
          properties: {
            personalized: {
              type: "array",
              items: { $ref: "#/components/schemas/StudentResource" },
            },
            trending: {
              type: "array",
              items: { $ref: "#/components/schemas/StudentResource" },
            },
            byDifficulty: {
              type: "object",
              properties: {
                beginner: {
                  type: "array",
                  items: { $ref: "#/components/schemas/StudentResource" },
                },
                intermediate: {
                  type: "array",
                  items: { $ref: "#/components/schemas/StudentResource" },
                },
                advanced: {
                  type: "array",
                  items: { $ref: "#/components/schemas/StudentResource" },
                },
              },
            },
            categoryStats: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  resources: { type: "number" },
                  avgRating: { type: "number" },
                },
              },
            },
          },
        },
        OperationResponse: {
          type: "object",
          properties: {
            success: { type: "boolean", example: true },
            message: {
              type: "string",
              example: "Operation completed successfully",
            },
          },
        },
      },
    },
    security: [
      {
        BearerAuth: [],
      },
    ],
  },
  apis: ["./src/routes/**/*.ts", "./src/controllers/**/*.ts", "./src/modules/**/*.ts"],
};

export const specs = (() => {
  try {
    return swaggerJsdoc(options);
  } catch (err) {
    // Swagger docs are helpful but should never block local dev or production boot.
    // This catches issues with transitive deps (e.g. doctrine/esutils) across Node versions.
    // eslint-disable-next-line no-console
    console.warn(
      "[swagger] Failed to generate OpenAPI spec; continuing without docs generation.",
      err,
    );

    return {
      ...(options.definition ?? {}),
      paths: {},
    };
  }
})();
