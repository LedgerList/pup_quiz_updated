# AI Quiz Generator Service

This application uses a Python Flask service to handle AI quiz generation using Google's Gemini 2.0 Flash API.

## Setup Instructions

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Python Service

```bash
python app.py
```

The service will run on `http://localhost:5000` by default.

### 3. Configure Laravel Environment

Add the following to your `.env` file:

```env
PYTHON_SERVICE_URL=http://localhost:5000
```

If your Python service runs on a different port or host, update this value accordingly.

### 4. Running the Service

#### Option 1: Direct Python
```bash
python app.py
```

#### Option 2: Using Gunicorn (Production)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

#### Option 3: Using PM2 (Process Manager)
```bash
npm install -g pm2
pm2 start app.py --name ai-quiz-service --interpreter python3
pm2 save
```

## Features

- **Rate Limiting**: Built-in rate limiting to prevent 429 errors
- **Retry Logic**: Automatic retries with exponential backoff
- **Error Handling**: Comprehensive error handling and logging
- **CORS Enabled**: Cross-origin requests enabled for Laravel integration

## API Endpoints

### POST /generate-quiz

Generates quiz questions using AI.

**Request Body:**
```json
{
  "topics": "Mathematics, Algebra, Geometry",
  "num_questions": 10,
  "seconds_per_question": 30
}
```

**Response:**
```json
{
  "success": true,
  "questions": [
    {
      "question": "What is 2 + 2?",
      "options": {
        "A": "3",
        "B": "4",
        "C": "5",
        "D": "6"
      },
      "correct_answer": "B",
      "explanation": "2 + 2 equals 4"
    }
  ],
  "count": 10
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00"
}
```

## Troubleshooting

### Rate Limit Errors (429)

The service includes rate limiting (2 seconds between requests). If you still get 429 errors:
1. Increase `min_request_interval` in `app.py`
2. Use multiple API keys with load balancing
3. Implement request queuing

### Connection Errors

If Laravel cannot connect to the Python service:
1. Verify the service is running: `curl http://localhost:5000/health`
2. Check the `PYTHON_SERVICE_URL` in `.env`
3. Ensure firewall allows connections on port 5000

### JSON Parse Errors

If questions fail to parse:
- The service includes automatic retry logic
- Check logs for the raw AI response
- Try with simpler topics

