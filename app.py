from flask import Flask, request, jsonify
import os
import base64
from dotenv import load_dotenv
import tempfile
from google import generativeai as genai
from flask_cors import CORS
import json
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure CORS properly - allow requests from any origin
CORS(app, resources={r"/*": {"origins": "*"}})

# Use the API key from environment variables or fallback to the hardcoded one
API_KEY = os.getenv("GOOGLE_API_KEY", "AIzaSyBTpvDoKRGblWhzA-yV4mRQhhpGZ7S4P5w")

genai.configure(api_key=API_KEY)

@app.route('/generate-quiz', methods=['POST', 'OPTIONS'])
def generate_quiz():
    """Generate quiz from uploaded study materials (images or text)"""
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        body = request.get_json(force=True) or {}
        image_data = body.get('image')  # Keep for backward compatibility
        file_data = body.get('file') or image_data  # Support both 'file' and 'image'
        text_content = body.get('text', '')
        topic = body.get('topic', '')
        difficulty = body.get('difficulty', 'medium')  # easy, medium, hard
        num_questions = int(body.get('num_questions', 10))
        question_type = body.get('question_type', 'multiple-choice')  # multiple-choice, true-false, short-answer
        file_type = body.get('file_type', '')
        file_name = body.get('file_name', '')
        
        # Validate input
        if not file_data and not text_content and not topic:
            return jsonify({'error': 'Please provide a file (image/PDF), text content, or topic'}), 400
        
        # Process file (image or PDF) if provided
        file_parts = []
        
        if file_data and ',' in file_data:
            try:
                base64_data = file_data.split(',')[1] if ',' in file_data else file_data
                binary_data = base64.b64decode(base64_data)
                
                # Determine MIME type
                if file_type == 'application/pdf' or (file_name and file_name.lower().endswith('.pdf')):
                    # Handle PDF
                    mime_type = 'application/pdf'
                elif file_type.startswith('image/'):
                    # Handle image
                    mime_type = file_type
                else:
                    # Try to detect from base64 prefix or default to image/jpeg
                    if file_data.startswith('data:application/pdf'):
                        mime_type = 'application/pdf'
                    elif file_data.startswith('data:image/'):
                        mime_type = file_data.split(';')[0].split(':')[1]
                    else:
                        mime_type = 'image/jpeg'  # Default fallback
                
                file_parts.append({'mime_type': mime_type, 'data': binary_data})
            except Exception as e:
                return jsonify({'error': f'Invalid file data: {str(e)}'}), 400
        
        # Create prompt for quiz generation
        prompt = f"""
        Generate a comprehensive quiz based on the provided content.
        
        Requirements:
        - Number of questions: {num_questions}
        - Difficulty level: {difficulty}
        - Question type: {question_type}
        - Topic: {topic if topic else 'Based on the provided content'}
        
        For each question, provide:
        1. Question text (clear and specific)
        2. Options (if multiple-choice: 4 options labeled A, B, C, D)
        3. Correct answer
        4. Explanation (brief explanation of why the answer is correct)
        5. Points (assign points based on difficulty: easy=1, medium=2, hard=3)
        
        Question Type Guidelines:
        - Multiple Choice: Provide 4 options, one clearly correct
        - True/False: Provide only True or False options
        - Short Answer: Provide the expected answer and key points to look for
        
        Format the response as JSON with this structure:
        {{
            "quiz_title": "Title for the quiz",
            "quiz_description": "Brief description of the quiz",
            "topic": "Main topic covered",
            "difficulty": "{difficulty}",
            "questions": [
                {{
                    "question": "Question text here?",
                    "type": "{question_type}",
                    "options": [
                        {{"text": "Option A", "isCorrect": false}},
                        {{"text": "Option B", "isCorrect": true}},
                        {{"text": "Option C", "isCorrect": false}},
                        {{"text": "Option D", "isCorrect": false}}
                    ],
                    "correct_answer": "Option B",
                    "explanation": "Explanation of the correct answer",
                    "points": 2
                }}
            ]
        }}
        
        Ensure questions are:
        - Educational and relevant to the content
        - Varied in difficulty within the specified level
        - Clear and unambiguous
        - Cover different aspects of the topic
        - Have accurate answers with good explanations
        
        Return ONLY the JSON object, no additional text or formatting.
        """
        
        # Add text content to prompt if provided
        if text_content:
            prompt = f"{prompt}\n\nContent to base quiz on:\n{text_content}"
        
        # Add topic if provided
        if topic:
            prompt = f"{prompt}\n\nFocus topic: {topic}"
        
        try:
            model = genai.GenerativeModel('gemini-2.0-flash')
            
            # Generate quiz
            if file_parts:
                # If file (image or PDF) provided, use multimodal
                content_parts = file_parts + [prompt]
            else:
                # Text only
                content_parts = [prompt]
            
            response = model.generate_content(content_parts)
            response_text = response.text.strip()
            
            # Clean JSON response - handle various markdown code block formats
            # Remove markdown code blocks
            if "```json" in response_text:
                # Extract content between ```json and ```
                start_idx = response_text.find("```json") + 7
                end_idx = response_text.find("```", start_idx)
                if end_idx != -1:
                    response_text = response_text[start_idx:end_idx].strip()
            elif "```" in response_text:
                # Extract content between ``` and ```
                start_idx = response_text.find("```") + 3
                end_idx = response_text.find("```", start_idx)
                if end_idx != -1:
                    response_text = response_text[start_idx:end_idx].strip()
            
            # Remove any leading/trailing whitespace
            response_text = response_text.strip()
            
            # Try to find JSON object in the response if it's embedded in text
            # Look for the first { and last } to extract JSON
            first_brace = response_text.find('{')
            last_brace = response_text.rfind('}')
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                response_text = response_text[first_brace:last_brace + 1]
            
            quiz_data = json.loads(response_text)
            
            # Validate and normalize quiz data
            if 'questions' not in quiz_data:
                return jsonify({'error': 'Invalid quiz format generated'}), 500
            
            # Ensure all questions have required fields
            for question in quiz_data['questions']:
                if 'points' not in question:
                    question['points'] = 2 if difficulty == 'medium' else (1 if difficulty == 'easy' else 3)
                if 'type' not in question:
                    question['type'] = question_type
                if 'explanation' not in question:
                    question['explanation'] = 'No explanation provided'
            
            return jsonify({
                'success': True,
                'quiz': quiz_data
            })
            
        except json.JSONDecodeError as e:
            return jsonify({
                'error': 'Failed to parse quiz data',
                'details': str(e),
                'raw_response': response_text[:500] if 'response_text' in locals() else None
            }), 500
        except Exception as e:
            return jsonify({'error': f'Error generating quiz: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate-quiz-from-text', methods=['POST', 'OPTIONS'])
def generate_quiz_from_text():
    """Generate quiz from text description or topic"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json(force=True) or {}
        topic = data.get('topic', '')
        description = data.get('description', '')
        difficulty = data.get('difficulty', 'medium')
        num_questions = int(data.get('num_questions', 10))
        question_type = data.get('question_type', 'multiple-choice')
        
        if not topic and not description:
            return jsonify({'error': 'Please provide a topic or description'}), 400
        
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        prompt = f"""
        Create a comprehensive quiz based on the following information:
        
        Topic: {topic if topic else 'General Knowledge'}
        Description: {description if description else 'No specific description provided'}
        Difficulty: {difficulty}
        Number of questions: {num_questions}
        Question type: {question_type}
        
        Generate {num_questions} {question_type} questions that:
        - Are appropriate for {difficulty} difficulty level
        - Cover various aspects of the topic
        - Are clear and well-formulated
        - Have one clearly correct answer
        - Include educational explanations
        
        Format as JSON:
        {{
            "quiz_title": "Quiz Title",
            "quiz_description": "Description",
            "topic": "{topic}",
            "difficulty": "{difficulty}",
            "questions": [
                {{
                    "question": "Question text?",
                    "type": "{question_type}",
                    "options": [
                        {{"text": "Option A", "isCorrect": false}},
                        {{"text": "Option B", "isCorrect": true}},
                        {{"text": "Option C", "isCorrect": false}},
                        {{"text": "Option D", "isCorrect": false}}
                    ],
                    "correct_answer": "Option B",
                    "explanation": "Why this is correct",
                    "points": 2
                }}
            ]
        }}
        
        Return ONLY the JSON object.
        """
        
        try:
            response = model.generate_content(prompt)
            response_text = response.text.strip()
            
            # Clean JSON - handle various markdown code block formats
            if "```json" in response_text:
                start_idx = response_text.find("```json") + 7
                end_idx = response_text.find("```", start_idx)
                if end_idx != -1:
                    response_text = response_text[start_idx:end_idx].strip()
            elif "```" in response_text:
                start_idx = response_text.find("```") + 3
                end_idx = response_text.find("```", start_idx)
                if end_idx != -1:
                    response_text = response_text[start_idx:end_idx].strip()
            
            response_text = response_text.strip()
            
            # Try to find JSON object in the response if it's embedded in text
            first_brace = response_text.find('{')
            last_brace = response_text.rfind('}')
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                response_text = response_text[first_brace:last_brace + 1]
            
            quiz_data = json.loads(response_text)
            
            # Normalize questions
            for question in quiz_data.get('questions', []):
                if 'points' not in question:
                    question['points'] = 2 if difficulty == 'medium' else (1 if difficulty == 'easy' else 3)
                if 'type' not in question:
                    question['type'] = question_type
            
            return jsonify({
                'success': True,
                'quiz': quiz_data
            })
            
        except json.JSONDecodeError as e:
            return jsonify({
                'error': 'Failed to parse quiz data',
                'details': str(e)
            }), 500
        except Exception as e:
            return jsonify({'error': f'Error generating quiz: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate-custom-prompt-quiz', methods=['POST', 'OPTIONS'])
def generate_custom_prompt_quiz():
    """Generate quiz from a custom prompt"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json(force=True) or {}
        custom_prompt = data.get('prompt', '')
        num_questions = int(data.get('num_questions', 10))
        difficulty = data.get('difficulty', 'medium')
        question_type = data.get('question_type', 'multiple-choice')
        
        if not custom_prompt or len(custom_prompt.strip()) < 10:
            return jsonify({'error': 'Custom prompt is required and must be at least 10 characters'}), 400
        
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        prompt = f"""
        Based on the following custom prompt, generate a comprehensive quiz:
        
        Custom Prompt: {custom_prompt}
        
        Requirements:
        - Number of questions: {num_questions}
        - Difficulty: {difficulty}
        - Question type: {question_type}
        
        Create questions that directly address the custom prompt and cover its key aspects.
        
        Format as JSON:
        {{
            "quiz_title": "Relevant Quiz Title",
            "quiz_description": "Description based on custom prompt",
            "topic": "Extracted topic",
            "difficulty": "{difficulty}",
            "questions": [
                {{
                    "question": "Question text?",
                    "type": "{question_type}",
                    "options": [
                        {{"text": "Option A", "isCorrect": false}},
                        {{"text": "Option B", "isCorrect": true}},
                        {{"text": "Option C", "isCorrect": false}},
                        {{"text": "Option D", "isCorrect": false}}
                    ],
                    "correct_answer": "Option B",
                    "explanation": "Explanation",
                    "points": 2
                }}
            ]
        }}
        
        Return ONLY the JSON object.
        """
        
        try:
            response = model.generate_content(prompt)
            response_text = response.text.strip()
            
            # Clean JSON - handle various markdown code block formats
            if "```json" in response_text:
                start_idx = response_text.find("```json") + 7
                end_idx = response_text.find("```", start_idx)
                if end_idx != -1:
                    response_text = response_text[start_idx:end_idx].strip()
            elif "```" in response_text:
                start_idx = response_text.find("```") + 3
                end_idx = response_text.find("```", start_idx)
                if end_idx != -1:
                    response_text = response_text[start_idx:end_idx].strip()
            
            response_text = response_text.strip()
            
            # Try to find JSON object in the response if it's embedded in text
            first_brace = response_text.find('{')
            last_brace = response_text.rfind('}')
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                response_text = response_text[first_brace:last_brace + 1]
            
            quiz_data = json.loads(response_text)
            
            # Normalize
            for question in quiz_data.get('questions', []):
                if 'points' not in question:
                    question['points'] = 2 if difficulty == 'medium' else (1 if difficulty == 'easy' else 3)
                if 'type' not in question:
                    question['type'] = question_type
            
            return jsonify({
                'success': True,
                'quiz': quiz_data
            })
            
        except json.JSONDecodeError as e:
            return jsonify({
                'error': 'Failed to parse quiz data',
                'details': str(e)
            }), 500
        except Exception as e:
            return jsonify({'error': f'Error generating quiz: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Quiz Generation API',
        'version': '1.0.0'
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8800))
    print(f"Starting Quiz Generation API server on http://localhost:{port}")
    app.run(debug=True, port=port, host='0.0.0.0')

