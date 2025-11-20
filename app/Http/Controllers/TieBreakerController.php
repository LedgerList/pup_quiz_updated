<?php

namespace App\Http\Controllers;

use App\Events\QuizEvent;
use App\Models\Lobby;
use App\Models\Participants;
use App\Models\PointsHistory;
use App\Models\SubjectQuestion;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class TieBreakerController extends Controller
{
    /**
     * Check if there are ties in the leaderboard and return tied participants
     * 
     * @param int $lobby_id
     * @param int $subject_id
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkForTies($lobby_id, $subject_id)
    {
        try {
            $lobby = Lobby::find($lobby_id);
            if (!$lobby) {
                return response()->json([
                    'success' => false,
                    'message' => 'Lobby not found'
                ], 404);
            }

            // Get all participants with their scores
            $participants = Participants::where('lobby_code', $lobby->lobby_code)
                ->where('subject_id', $subject_id)
                ->where('is_approved', '2')
                ->orderBy('score', 'desc')
                ->orderBy('created_at', 'asc')
                ->get();

            if ($participants->isEmpty()) {
                return response()->json([
                    'success' => false,
                    'message' => 'No participants found'
                ], 404);
            }

            // Group participants by score to find ties
            $scoreGroups = $participants->groupBy('score');
            $ties = [];
            $highestScore = null;

            foreach ($scoreGroups as $score => $group) {
                if ($group->count() > 1) {
                    // Found a tie
                    if ($highestScore === null) {
                        $highestScore = $score;
                    }
                    
                    // Only consider ties for the highest score
                    if ($score == $highestScore) {
                        $ties = $group->map(function($participant) {
                            return [
                                'id' => $participant->id,
                                'team' => $participant->team,
                                'score' => $participant->score
                            ];
                        })->values()->toArray();
                    }
                }
            }

            return response()->json([
                'success' => true,
                'has_ties' => !empty($ties),
                'tied_participants' => $ties,
                'highest_score' => $highestScore
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error checking for ties: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Start tie breaker round
     * 
     * @param Request $request
     * @param int $lobby_id
     * @param int $subject_id
     * @return \Illuminate\Http\JsonResponse
     */
    public function startTieBreaker(Request $request, $lobby_id, $subject_id)
    {
        try {
            $lobby = Lobby::find($lobby_id);
            if (!$lobby) {
                return response()->json([
                    'success' => false,
                    'message' => 'Lobby not found'
                ], 404);
            }

            // Check for ties first
            $tieCheck = $this->checkForTies($lobby_id, $subject_id);
            $tieData = json_decode($tieCheck->getContent(), true);

            if (!$tieData['has_ties']) {
                return response()->json([
                    'success' => false,
                    'message' => 'No ties found. Tie breaker not needed.'
                ], 400);
            }

            // Start with Easy round
            $lobby->update([
                'tie_breaker_active' => true,
                'tie_breaker_round' => 'easy',
                'tie_breaker_question_num' => 1
            ]);

            // Get first tie breaker question (Easy difficulty)
            $question = $this->getTieBreakerQuestion($lobby_id, $subject_id, 'easy', 1);

            // Broadcast tie breaker start event
            broadcast(new QuizEvent('tie-breaker-started', $question, 1, $lobby_id, 'easy'));

            return response()->json([
                'success' => true,
                'message' => 'Tie breaker round started',
                'round' => 'easy',
                'question' => $question,
                'tied_participants' => $tieData['tied_participants']
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error starting tie breaker: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Get tie breaker question for a specific round and question number
     * 
     * @param int $lobby_id
     * @param int $subject_id
     * @param string $difficulty (easy, average, hard)
     * @param int $question_num
     * @return array|null
     */
    public function getTieBreakerQuestion($lobby_id, $subject_id, $difficulty, $question_num)
    {
        $question = SubjectQuestion::where('subject_id', $subject_id)
            ->where('difficulty', $difficulty)
            ->where('deleted', 0)
            ->skip($question_num - 1)
            ->first();

        if (!$question) {
            return null;
        }

        $options = json_decode($question->options, true);
        
        return [
            'id' => $question->id,
            'question' => $question->question,
            'type' => $question->type,
            'difficulty' => $question->difficulty,
            'options' => $options,
            'time_limit' => $question->timeLimit ?? 30,
            'points' => $question->points ?? 10
        ];
    }

    /**
     * Get current tie breaker question
     * 
     * @param int $lobby_id
     * @param int $subject_id
     * @return \Illuminate\Http\JsonResponse
     */
    public function getCurrentTieBreakerQuestion($lobby_id, $subject_id)
    {
        try {
            $lobby = Lobby::find($lobby_id);
            if (!$lobby || !$lobby->tie_breaker_active) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tie breaker is not active'
                ], 400);
            }

            $question = $this->getTieBreakerQuestion(
                $lobby_id,
                $subject_id,
                $lobby->tie_breaker_round,
                $lobby->tie_breaker_question_num
            );

            if (!$question) {
                return response()->json([
                    'success' => false,
                    'message' => 'No more questions available for this round'
                ], 404);
            }

            return response()->json([
                'success' => true,
                'question' => $question,
                'round' => $lobby->tie_breaker_round,
                'question_num' => $lobby->tie_breaker_question_num
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error getting tie breaker question: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Process tie breaker answer and move to next round if needed
     * 
     * @param Request $request
     * @param int $lobby_id
     * @param int $subject_id
     * @return \Illuminate\Http\JsonResponse
     */
    public function processTieBreakerAnswer(Request $request, $lobby_id, $subject_id)
    {
        try {
            $request->validate([
                'participant_id' => 'required|integer',
                'answer' => 'required|string',
                'question_id' => 'required|integer'
            ]);

            $lobby = Lobby::find($lobby_id);
            if (!$lobby || !$lobby->tie_breaker_active) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tie breaker is not active'
                ], 400);
            }

            $participant = Participants::find($request->participant_id);
            if (!$participant) {
                return response()->json([
                    'success' => false,
                    'message' => 'Participant not found'
                ], 404);
            }

            $question = SubjectQuestion::find($request->question_id);
            if (!$question) {
                return response()->json([
                    'success' => false,
                    'message' => 'Question not found'
                ], 404);
            }

            // Check if answer is correct
            $isCorrect = $this->checkAnswer($question, $request->answer);
            $pointsAwarded = $isCorrect ? ($question->points ?? 10) : 0;

            // Store tie breaker points separately (we'll add a field for this)
            // For now, we'll use a special prefix in points_history
            PointsHistory::create([
                'participant_id' => $participant->id,
                'question_id' => $question->id,
                'lobby_id' => $lobby_id,
                'subject_id' => $subject_id,
                'answer' => $request->answer,
                'points' => $pointsAwarded,
                'question' => $question->question,
                'is_tie_breaker' => true,
                'tie_breaker_round' => $lobby->tie_breaker_round
            ]);

            // Update participant's tie breaker score (we'll track this separately)
            // For now, add to a tie_breaker_score field (need migration)
            // Or we can calculate it from points_history with is_tie_breaker flag

            return response()->json([
                'success' => true,
                'is_correct' => $isCorrect,
                'points_awarded' => $pointsAwarded,
                'message' => $isCorrect ? 'Correct answer!' : 'Incorrect answer'
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error processing answer: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Move to next tie breaker round or determine winner
     * 
     * @param Request $request
     * @param int $lobby_id
     * @param int $subject_id
     * @return \Illuminate\Http\JsonResponse
     */
    public function nextTieBreakerRound(Request $request, $lobby_id, $subject_id)
    {
        try {
            $lobby = Lobby::find($lobby_id);
            if (!$lobby || !$lobby->tie_breaker_active) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tie breaker is not active'
                ], 400);
            }

            // Calculate tie breaker scores for all tied participants
            $tieBreakerScores = $this->calculateTieBreakerScores($lobby_id, $subject_id, $lobby->tie_breaker_round);

            // Check if we have a clear winner
            $maxScore = max($tieBreakerScores);
            $winners = array_keys(array_filter($tieBreakerScores, function($score) use ($maxScore) {
                return $score == $maxScore;
            }));

            // If only one winner, end tie breaker
            if (count($winners) == 1) {
                $lobby->update([
                    'tie_breaker_active' => false,
                    'tie_breaker_round' => null,
                    'tie_breaker_question_num' => 0
                ]);

                broadcast(new QuizEvent('tie-breaker-ended', null, null, $lobby_id, null));

                return response()->json([
                    'success' => true,
                    'winner_determined' => true,
                    'winner_id' => $winners[0],
                    'message' => 'Tie breaker completed. Winner determined.'
                ], 200);
            }

            // Move to next round: easy -> average -> hard
            $rounds = ['easy', 'average', 'hard'];
            $currentIndex = array_search($lobby->tie_breaker_round, $rounds);
            
            if ($currentIndex < count($rounds) - 1) {
                // Move to next round
                $nextRound = $rounds[$currentIndex + 1];
                $lobby->update([
                    'tie_breaker_round' => $nextRound,
                    'tie_breaker_question_num' => 1
                ]);

                $question = $this->getTieBreakerQuestion($lobby_id, $subject_id, $nextRound, 1);

                broadcast(new QuizEvent('tie-breaker-round-changed', $question, 1, $lobby_id, $nextRound));

                return response()->json([
                    'success' => true,
                    'round' => $nextRound,
                    'question' => $question,
                    'tied_participants' => $winners,
                    'message' => "Moving to {$nextRound} round"
                ], 200);
            } else {
                // All rounds completed, determine winner by earliest correct answer
                $winner = $this->determineWinnerByTime($lobby_id, $subject_id, $winners);
                
                $lobby->update([
                    'tie_breaker_active' => false,
                    'tie_breaker_round' => null,
                    'tie_breaker_question_num' => 0
                ]);

                broadcast(new QuizEvent('tie-breaker-ended', null, null, $lobby_id, null));

                return response()->json([
                    'success' => true,
                    'winner_determined' => true,
                    'winner_id' => $winner,
                    'message' => 'Tie breaker completed. Winner determined by earliest correct answer.'
                ], 200);
            }

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error moving to next round: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Calculate tie breaker scores for participants in current round
     */
    private function calculateTieBreakerScores($lobby_id, $subject_id, $round)
    {
        $lobby = Lobby::find($lobby_id);
        $participants = Participants::where('lobby_code', $lobby->lobby_code)
            ->where('subject_id', $subject_id)
            ->where('is_approved', '2')
            ->get();

        $scores = [];
        foreach ($participants as $participant) {
            $tieBreakerPoints = PointsHistory::where('participant_id', $participant->id)
                ->where('lobby_id', $lobby_id)
                ->where('is_tie_breaker', true)
                ->where('tie_breaker_round', $round)
                ->sum('points');
            
            $scores[$participant->id] = $tieBreakerPoints;
        }

        return $scores;
    }

    /**
     * Determine winner by earliest correct answer time
     */
    private function determineWinnerByTime($lobby_id, $subject_id, $participantIds)
    {
        $earliest = PointsHistory::whereIn('participant_id', $participantIds)
            ->where('lobby_id', $lobby_id)
            ->where('is_tie_breaker', true)
            ->where('points', '>', 0)
            ->orderBy('created_at', 'asc')
            ->first();

        return $earliest ? $earliest->participant_id : $participantIds[0];
    }

    /**
     * Check if answer is correct
     */
    private function checkAnswer($question, $answer)
    {
        $options = json_decode($question->options, true);
        
        if ($question->type === 'multiple-choice') {
            // Find correct option
            foreach ($options as $option) {
                if (isset($option['isCorrect']) && $option['isCorrect']) {
                    return strtoupper(trim($answer)) === strtoupper(trim($option['text']));
                }
            }
        } elseif ($question->type === 'true-false') {
            $correctAnswer = $question->trueFalseAnswer ? 'true' : 'false';
            return strtolower(trim($answer)) === strtolower($correctAnswer);
        } elseif ($question->type === 'short-answer') {
            return strtolower(trim($answer)) === strtolower(trim($question->shortAnswer));
        }

        return false;
    }
}
