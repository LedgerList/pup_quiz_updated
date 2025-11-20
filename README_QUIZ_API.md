# Quiz Generation API

A Flask-based API service that generates quizzes using Google's Gemini AI. This service can create quizzes from:
- Uploaded images (study materials, documents)
- Text content
- Custom prompts
- Topics

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables:
Create a `.env` file in the root directory:
```
GOOGLE_API_KEY=your_google_api_key_here
PORT=8800
```

3. Run the server:
```bash
python app.py
```

The server will start on `http://localhost:8800`

## API Endpoints

### 1. Generate Quiz from Image/Text
**POST** `/generate-quiz`

Generate a quiz from uploaded study materials (image or text).

**Request Body:**
```json
{
  "image": "data:image/jpeg;base64,...",  // Optional: base64 encoded image
  "text": "Study material text content",  // Optional: text content
  "topic": "Biology",                      // Optional: topic name
  "difficulty": "medium",                  // easy, medium, hard
  "num_questions": 10,                    // Number of questions
  "question_type": "multiple-choice"       // multiple-choice, true-false, short-answer
}
```

**Response:**
```json
{
  "success": true,
  "quiz": {
    "quiz_title": "Quiz Title",
    "quiz_description": "Description",
    "topic": "Topic Name",
    "difficulty": "medium",
    "questions": [
      {
        "question": "Question text?",
        "type": "multiple-choice",
        "options": [
          {"text": "Option A", "isCorrect": false},
          {"text": "Option B", "isCorrect": true},
          {"text": "Option C", "isCorrect": false},
          {"text": "Option D", "isCorrect": false}
        ],
        "correct_answer": "Option B",
        "explanation": "Explanation text",
        "points": 2
      }
    ]
  }
}
```

### 2. Generate Quiz from Text/Topic
**POST** `/generate-quiz-from-text`

Generate a quiz from a topic or text description.

**Request Body:**
```json
{
  "topic": "Mathematics",
  "description": "Algebra and geometry concepts",
  "difficulty": "medium",
  "num_questions": 10,
  "question_type": "multiple-choice"
}
```

### 3. Generate Quiz from Custom Prompt
**POST** `/generate-custom-prompt-quiz`

Generate a quiz from a custom prompt.

**Request Body:**
```json
{
  "prompt": "Create a quiz about Philippine history focusing on the Spanish colonial period",
  "num_questions": 15,
  "difficulty": "hard",
  "question_type": "multiple-choice"
}
```

### 4. Health Check
**GET** `/health`

Check if the API is running.

**Response:**
```json
{
  "status": "healthy",
  "service": "Quiz Generation API",
  "version": "1.0.0"
}
```

## Question Types

- **multiple-choice**: 4 options (A, B, C, D), one correct answer
- **true-false**: True or False options
- **short-answer**: Open-ended question with expected answer

## Difficulty Levels

- **easy**: 1 point per question
- **medium**: 2 points per question
- **hard**: 3 points per question

## CORS

The API is configured to accept requests from any origin. Adjust CORS settings in `app.py` if needed for production.

## Error Handling

All endpoints return appropriate HTTP status codes:
- `200`: Success
- `400`: Bad Request (missing or invalid parameters)
- `500`: Internal Server Error

Error responses include an `error` field with details.

