<?php

namespace App\Http\Controllers;

use App\Events\QuizEvent;
use App\Models\EndedEvent;
use App\Models\LeaderboardLog;
use App\Models\Lobby;
use App\Models\Participants;
use App\Models\PointsHistory;
use App\Models\SubjectQuestion;
use App\Models\Subjects;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class QuizEventController extends Controller
{
    //


    public function closeEvent(Request $request, $id, $subject_id)
    {
        try {
            // Validate and decode leaderboard data
            if (!$request->has('leaderboard') || empty($request->leaderboard)) {
                return response()->json([
                    'status' => 400,
                    'message' => 'Leaderboard data is required.',
                ], 400);
            }

            $data = json_decode($request->leaderboard, true);
            
            // Check if JSON decode was successful
            if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
                return response()->json([
                    'status' => 400,
                    'message' => 'Invalid leaderboard data format.',
                ], 400);
            }

            // Check for ties before processing leaderboard
            $tieBreakerController = new \App\Http\Controllers\TieBreakerController();
            $tieCheckResponse = $tieBreakerController->checkForTies($id, $subject_id);
            $tieCheckData = json_decode($tieCheckResponse->getContent(), true);

            // If there are ties, return a response indicating tie breaker is needed
            if ($tieCheckData['success'] && $tieCheckData['has_ties']) {
                return response()->json([
                    'status' => 409, // Conflict status code
                    'message' => 'Tie detected. Tie breaker round required.',
                    'has_ties' => true,
                    'tied_participants' => $tieCheckData['tied_participants'],
                    'highest_score' => $tieCheckData['highest_score']
                ], 409);
            }

            // Process leaderboard entries (no ties, proceed normally)
            $place = 1;
            foreach ($data as $item) {
                // Validate required fields
                if (!isset($item['id']) || !isset($item['score']) || !isset($item['subject_id'])) {
                    continue; // Skip invalid entries
                }

                LeaderboardLog::create([
                    'user_id' => Auth::id(),
                    'participant_id' => $item['id'],
                    'total_score' => $item['score'],
                    'place' => $place,
                    'subject_id' => $item['subject_id'],
                ]);
                $place++;
            }

            // Update lobby state
            Lobby::where('id', $id)->update([
                'reveal_answer' => 0,
                'started' => 0,
                'finished' => 0,
                'start_timer' => 0,
                'reveal_leaderboard' => 0,
                'reveal_options' => 0,
                'question_num' => 1,
                'current_level' => '',
                'levels_finished' => ''
            ]);

            // Create ended event record
            EndedEvent::create([
                "lobby_id" => $id
            ]);

            // Get lobby and subject
            $lobby = Lobby::find($id);
            
            if (!$lobby) {
                return response()->json([
                    'status' => 404,
                    'message' => 'Lobby not found.',
                ], 404);
            }

            // Update subject questions archive status
            SubjectQuestion::where('subject_id', $subject_id)->update([
                'archive' => 0
            ]);

            // Broadcast event closure
            broadcast(new QuizEvent('event-closed', null, null, $id, null));
            
            // Delete points history
            PointsHistory::where('lobby_id', $id)->delete();

            // Return success response
            return response()->json([
                'status' => 200,
                'message' => 'Event closed successfully.',
            ], 200);

        } catch (QueryException $e) {
            // Catch database query errors (SQL, constraint violations, etc.)
            return response()->json([
                'status' => 500,
                'message' => 'Database error occurred.',
                'error' => $e->getMessage(), // optional: remove in production
            ], 500);
        } catch (\Exception $e) {
            // Catch any other general errors
            return response()->json([
                'status' => 500,
                'message' => 'Unexpected error occurred.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    public function clearPrevData($id)
    {
        $lobby = Lobby::find($id);
        $code = $lobby->lobby_code;
        Participants::where('lobby_code', $code)->update([
            'score' => 0,
            'archive' => 0,
             'prev_answer_correct' => 0,
             'prev_answer' => NULL
            // add more fields as needed
        ]);
    }
}
