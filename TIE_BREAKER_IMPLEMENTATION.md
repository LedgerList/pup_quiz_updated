# Tie Breaker Round Implementation

## Overview
The Tie Breaker Round system has been implemented to determine winners when participants have the same score at the end of a quiz event.

## How It Works

### 1. **Tie Detection**
- When closing an event, the system automatically checks for ties in the leaderboard
- Ties are detected by grouping participants by their total score
- Only ties for the **highest score** trigger a tie breaker round

### 2. **Tie Breaker Rounds**
The tie breaker consists of **3 rounds** in order:
1. **Easy Round** - Questions with `difficulty = 'easy'`
2. **Average Round** - Questions with `difficulty = 'average'`
3. **Hard Round** - Questions with `difficulty = 'hard'`

### 3. **Process Flow**

#### Step 1: Event Closing
- When organizer tries to close an event via `closeEvent()` endpoint
- System checks for ties using `checkForTies()` method
- If ties are found, returns status `409` with tie information
- Event closing is **blocked** until tie breaker is completed

#### Step 2: Starting Tie Breaker
- Organizer calls `/tie-breaker/start/{lobby_id}/{subject_id}`
- System:
  - Activates tie breaker mode (`tie_breaker_active = true`)
  - Sets current round to `'easy'`
  - Gets first Easy question
  - Broadcasts `tie-breaker-started` event

#### Step 3: Answering Questions
- Tied participants answer tie breaker questions
- Answers are submitted via `/tie-breaker/answer/{lobby_id}/{subject_id}`
- Points are tracked separately with `is_tie_breaker = true` flag
- Each round's points are tracked by `tie_breaker_round` field

#### Step 4: Moving to Next Round
- After each question, organizer calls `/tie-breaker/next-round/{lobby_id}/{subject_id}`
- System calculates scores for current round
- **If clear winner found**: Tie breaker ends, winner is determined
- **If still tied**: Moves to next round (Easy → Average → Hard)
- **If all rounds completed and still tied**: Winner determined by earliest correct answer time

#### Step 5: Completion
- Once winner is determined:
  - `tie_breaker_active` is set to `false`
  - Tie breaker fields are reset
  - `tie-breaker-ended` event is broadcast
  - Event can now be closed normally

## Database Changes

### Lobby Table
- `tie_breaker_active` (boolean) - Indicates if tie breaker is currently active
- `tie_breaker_round` (enum: 'easy', 'average', 'hard') - Current tie breaker round
- `tie_breaker_question_num` (integer) - Current question number in the round

### Points History Table
- `is_tie_breaker` (boolean) - Marks if this point was earned in tie breaker
- `tie_breaker_round` (enum) - Which tie breaker round this point was earned in

## API Endpoints

### 1. Check for Ties
```
GET /tie-breaker/check/{lobby_id}/{subject_id}
```
**Response:**
```json
{
  "success": true,
  "has_ties": true/false,
  "tied_participants": [...],
  "highest_score": 100
}
```

### 2. Start Tie Breaker
```
POST /tie-breaker/start/{lobby_id}/{subject_id}
```
**Response:**
```json
{
  "success": true,
  "message": "Tie breaker round started",
  "round": "easy",
  "question": {...},
  "tied_participants": [...]
}
```

### 3. Get Current Question
```
GET /tie-breaker/question/{lobby_id}/{subject_id}
```
**Response:**
```json
{
  "success": true,
  "question": {...},
  "round": "easy",
  "question_num": 1
}
```

### 4. Submit Answer
```
POST /tie-breaker/answer/{lobby_id}/{subject_id}
Body: {
  "participant_id": 1,
  "answer": "A",
  "question_id": 5
}
```
**Response:**
```json
{
  "success": true,
  "is_correct": true,
  "points_awarded": 10,
  "message": "Correct answer!"
}
```

### 5. Move to Next Round
```
POST /tie-breaker/next-round/{lobby_id}/{subject_id}
```
**Response (if winner found):**
```json
{
  "success": true,
  "winner_determined": true,
  "winner_id": 1,
  "message": "Tie breaker completed. Winner determined."
}
```

**Response (if moving to next round):**
```json
{
  "success": true,
  "round": "average",
  "question": {...},
  "tied_participants": [...],
  "message": "Moving to average round"
}
```

## Integration Points

### Frontend Integration Needed
1. **Tie Detection UI**: Show modal/alert when ties are detected during event closing
2. **Tie Breaker Display**: Component to show:
   - Current round (Easy/Average/Hard)
   - Current question
   - Tied participants and their tie breaker scores
   - Progress indicator
3. **Answer Submission**: Interface for participants to submit tie breaker answers
4. **Winner Announcement**: Display winner after tie breaker completion

### Event Flow
1. Quiz ends → Check for ties
2. If ties exist → Show tie breaker prompt
3. Start tie breaker → Display Easy round question
4. Participants answer → Track scores
5. Move to next round → Continue until winner found
6. Winner determined → Allow event closing

## Important Notes

- **Tie breaker points are separate** from main quiz scores
- Only participants with the **highest tied score** participate
- Questions are selected from the same subject but filtered by difficulty
- If all 3 rounds complete with no clear winner, earliest correct answer wins
- Tie breaker must be completed before event can be closed

## Example Scenario

1. Quiz ends with 3 participants tied at 100 points
2. System detects tie → Blocks event closing
3. Organizer starts tie breaker → Easy round begins
4. All 3 participants answer Easy question → 2 get it correct (10 points each)
5. Still tied → Move to Average round
6. Average question → 1 participant gets it correct (10 points)
7. **Winner determined** → Tie breaker ends
8. Event can now be closed with proper rankings



