<?php

namespace App\Http\Controllers;

use App\Mail\EventInvitationMail;
use App\Models\Lobby;
use App\Models\Participants;
use App\Models\PointsHistory;
use App\Models\PreRegistration;
use App\Models\SubjectQuestion;
use App\Models\Subjects;
use Carbon\Carbon;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;

class ParticipantController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function verify(Request $request)
    {
        $name = $request->input("team_name");

        $participant = Participants::where("team", $name)->first();

        return response()->json([
            'exists' => $participant !== null,
            'id' => $participant?->id // Returns null if not found
        ]);
    }

    public function updateTeamCode($id, $code)
    {
        Participants::where('id', $id)->update([
            'lobby_code' => $code
        ]);
    }
    public function updateAns(Request $request)
    {
        // First, update the lobby, then retrieve it

        $participants = json_decode($request->input('participants'));
        foreach ($participants as $item) {

            $participant = Participants::find($item->id); // simpler than where(...)->first()

            if (!$participant) {
                continue; // Skip if participant not found
            }

            $updateData = [
                'prev_answer_correct' => $item->status == "correct" ? 1 : 0,
            ];

            // Get the current question from the request or use a default
            // We need question_id and lobby_id to properly update points_history
            $question_id = $item->question_id ?? null;
            $lobby_id = $item->lobby_id ?? null;
            
            if ($item->status == "correct") {
                $updateData['score'] = $participant->score + $item->points;
            }

            Participants::where('id', $item->id)->update($updateData);

            // Update or create points_history record with proper where conditions
            // Note: $item->id is the participant_id, $lobby_id should come from the item data
            if ($question_id && $lobby_id) {
                $pointsHistory = PointsHistory::where("participant_id", $item->id)
                    ->where("question_id", $question_id)
                    ->where("lobby_id", $lobby_id)
                    ->whereDate("created_at", \Carbon\Carbon::today())
                    ->first();

                if ($pointsHistory) {
                    // Update existing record - increment attempt count if answer changed
                    $oldPoints = $pointsHistory->points;
                    $pointsHistory->points = $item->status == "correct" ? $item->points : 0;
                    $pointsHistory->answer = $item->answer ?? $participant->prev_answer ?? "";
                    
                    // Increment attempt count if points changed (indicates answer change)
                    if ($oldPoints != $pointsHistory->points) {
                        $pointsHistory->attempt_answers = ($pointsHistory->attempt_answers ?? 1) + 1;
                    }
                    
                    $pointsHistory->save();
                } else {
                    // Create new record if doesn't exist
                    PointsHistory::create([
                        "participant_id" => $item->id,
                        "question_id" => $question_id,
                        "lobby_id" => $lobby_id,
                        "points" => $item->status == "correct" ? $item->points : 0,
                        "question" => $item->question ?? "Short Answer Question",
                        "answer" => $item->answer ?? $participant->prev_answer ?? "",
                        "attempt_answers" => 1
                    ]);
                }
            } else {
                // Log warning if required fields are missing
                \Log::warning("updateAns: Missing question_id or lobby_id for participant {$item->id}");
            }
        }
        return 1;
    }
    public function shortAnswer($id, $subject_id, Request $request)
    {
        $lobby = Lobby::find($id); // simpler than where(...)->first()

        if (!$lobby) {
            return response()->json(['error' => 'Lobby not found'], 404);
        }

        $query = Participants::where([
            ['lobby_code', '=', $lobby->lobby_code],
            ['subject_id', '=', $subject_id],
            ['archive', '=', 1],
            ['invitation_accepted', '=', true], // Only show participants who accepted invitation
        ]);

        // Filter by question_id if provided (to get answers for current question only)
        $question_id = $request->input('question_id');
        if ($question_id) {
            // Get participants and their answers from points_history for the current question
            $participants = $query->get()->map(function($participant) use ($question_id, $id) {
                // Get the LATEST answer from points_history for this specific question
                // Order by created_at DESC to get the most recent answer
                $pointsHistory = \App\Models\PointsHistory::where('participant_id', $participant->id)
                    ->where('question_id', $question_id)
                    ->where('lobby_id', $id)
                    ->orderBy('created_at', 'desc')
                    ->orderBy('id', 'desc') // Secondary sort by id for consistency
                    ->first();
                
                $prev_answer = "";
                $points = 0;
                
                // If answer exists in points_history, use it; otherwise check participant's prev_answer
                if ($pointsHistory && !empty($pointsHistory->answer)) {
                    $prev_answer = $pointsHistory->answer;
                    $points = $pointsHistory->points;
                } elseif (!empty($participant->prev_answer)) {
                    // Use participant's prev_answer if points_history doesn't have it
                    $prev_answer = $participant->prev_answer;
                }
                
                // Return sanitized data - exclude sensitive information
                return [
                    'id' => $participant->id,
                    'team' => $participant->team,
                    'prev_answer' => $prev_answer,
                    'points' => $points,
                    // Exclude sensitive fields: team_leader_email, student_number, contact_number, etc.
                ];
            });
        } else {
            // If no question_id provided, return all participants (backward compatibility)
            // Still sanitize to exclude sensitive data
            $participants = $query->get()->map(function($participant) {
                return [
                    'id' => $participant->id,
                    'team' => $participant->team,
                    'score' => $participant->score,
                    'prev_answer' => $participant->prev_answer ?? "",
                    // Exclude sensitive fields
                ];
            });
        }

        return $participants;
    }
    public function leaderboard($id, $subject_id)
    {
        $lobby = Lobby::where("id", $id)->first();

        if (!$lobby) {
            return response()->json(['error' => 'Lobby not found'], 404);
        }

        // Get all participants - this is for overall leaderboard
        // Answers for specific questions are handled by currentQuestionLeaderboard()
        $participants = Participants::where('lobby_code', $lobby->lobby_code)
            ->where("subject_id", $subject_id)
            ->where("is_approved", "2")
            ->get();

        // Sanitize data - exclude sensitive information
        $participants = $participants->map(function($participant) {
            // Ensure prev_answer is never null
            if (is_null($participant->prev_answer)) {
                $participant->prev_answer = "";
            }
            
            // Return only safe fields for leaderboard display
            return [
                'id' => $participant->id,
                'team' => $participant->team,
                'score' => $participant->score,
                'prev_answer' => $participant->prev_answer,
                'prev_answer_correct' => $participant->prev_answer_correct,
                'rank' => null, // Will be set by frontend
                // Exclude sensitive fields: team_leader_email, student_number, contact_number, etc.
            ];
        });

        // Sort by score descending, then by created_at ascending
        return $participants->sortByDesc('score')
            ->sortBy('created_at')
            ->values();
    }
    // public function currentQuestionLeaderboard($id, $question_id)
    // {
    //     $subQuery = DB::table('points_history')
    //         ->select(DB::raw('MAX(created_at) as latest_created_at'), 'participant_id')
    //         ->where('lobby_id', $id)
    //         ->where('question_id', $question_id)
    //         ->groupBy('participant_id');

    //     // Join the subquery to get full rows
    //     $history = DB::table('points_history as ph')
    //         ->joinSub($subQuery, 'latest', function ($join) {
    //             $join->on('ph.participant_id', '=', 'latest.participant_id')
    //                 ->on('ph.created_at', '=', 'latest.latest_created_at');
    //         })
    //         ->join('participants as p', 'ph.participant_id', '=', 'p.id') // JOIN with participants
    //         ->where('ph.lobby_id', $id)
    //         ->where('ph.question_id', $question_id)
    //         ->select(
    //             'ph.*',
    //             'p.team as participant_name' // select participant name (or any field you need)
    //         )
    //         ->get();

    //     return $history;
    // }

    public function managePreRegistration(Request $request)
    {

        try {

            $participant_exist = Participants::find($request->participant_id);

            if (!$participant_exist) {
                return response()->json([
                    'success' => false,
                    'message' => 'Participant not found.',
                ], 404);
            }

            // Example insert (replace with your actual model and logic)
            $participant = PreRegistration::create([
                "user_id"=>Auth::user()->id,
                'status' => $request->status,
                'participant_id' => $request->participant_id,
                'lobby_id' => $request->lobby_id,
                'comment' => $request->comment

            ]);

            $participant = Participants::where("id", $request->participant_id)->first();

            $participant->is_approved = $request->status == 1 ? 1 : 2; // 2 IS APPROVED
            $participant->save();


            $subject = Subjects::where("lobby_id", $request->lobby_id)->first();
            $subject_id =  $participant->subject_id;

            $link = $request->status == 1 ? "#" : url("questionnaire/$request->lobby_id/$request->participant_id/$subject_id");
            $subject = $request->status == 1 ? "We regret to inform you that your registration has been declined." : "Congratulations You're invited for a quiz event";

            Mail::to($participant->team_leader_email)->send(new EventInvitationMail($participant->team, $participant->team_leader_email, $subject, $link));

            // Return success response
            return response()->json([
                'success' => true,
                'message' => $request->status == 1 ?  'Pre-registration rejected!' : 'Pre-registration approved!',
                'data' => $participant,
            ], 201); // 201 = Created
        } catch (\Exception $e) {
            // Return error response if something goes wrong
            return response()->json([
                'success' => false,
                'message' => 'Something went wrong during registration.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
    public function currentQuestionLeaderboard($id, $question_id)
    {
        // Archive the question
        SubjectQuestion::where('id', $question_id)->update([
            'archive' => '1',
        ]);

        // Get all participants for this lobby
        $lobby = Lobby::find($id);
        if (!$lobby) {
            return response()->json(['error' => 'Lobby not found'], 404);
        }

        // Get the subject_id from the question to filter participants
        $question = SubjectQuestion::find($question_id);
        $subject_id = $question ? $question->subject_id : null;

        // Get all participants first - only those who accepted invitation and match the subject
        $participants = Participants::where('lobby_code', $lobby->lobby_code)
            ->where('is_approved', '2')
            ->where('invitation_accepted', true) // Only show participants who accepted invitation
            ->when($subject_id, function($query) use ($subject_id) {
                return $query->where('subject_id', $subject_id);
            })
            ->get()
            ->unique('id'); // Remove duplicates by participant ID

        // Get the latest answer from points_history for each participant for this question
        $leaderboardData = $participants->map(function($participant) use ($question_id, $id) {
            // Get the LATEST answer from points_history (most recent by created_at and id)
            $pointsHistory = PointsHistory::where('participant_id', $participant->id)
                ->where('question_id', $question_id)
                ->where('lobby_id', $id)
                ->orderBy('created_at', 'desc')
                ->orderBy('id', 'desc')
                ->first();

            // If no answer in points_history, check participant's prev_answer
            if (!$pointsHistory) {
                // Try to get question text for display
                $question = \App\Models\SubjectQuestion::find($question_id);
                return [
                    'participant_id' => $participant->id,
                    'participant_name' => $participant->team, // Only team name, no sensitive data
                    'question_id' => $question_id,
                    'lobby_id' => $id,
                    'question' => $question ? $question->question : '',
                    'answer' => !empty($participant->prev_answer) ? $participant->prev_answer : '',
                    'points' => 0,
                    'created_at' => $participant->created_at,
                    // Exclude sensitive participant data
                ];
            }

            return [
                'participant_id' => $participant->id,
                'participant_name' => $participant->team, // Only team name, no sensitive data
                'question_id' => $pointsHistory->question_id,
                'lobby_id' => $pointsHistory->lobby_id,
                'question' => $pointsHistory->question,
                'answer' => !empty($pointsHistory->answer) ? $pointsHistory->answer : '',
                'points' => $pointsHistory->points ?? 0,
                'created_at' => $pointsHistory->created_at,
                // Exclude sensitive participant data
            ];
        })->sortByDesc('points')
          ->sortBy('created_at')
          ->values();

        return $leaderboardData;
    }
    public function teams($id, $subject_id)
    {
        $lobby =  Lobby::where("id", $id)->first();

        // Only show participants who have accepted the invitation via the invitation link
        $teams = Participants::where("lobby_code", $lobby->lobby_code)
            ->where("subject_id", $subject_id)
            ->where("is_approved","2")
            ->where("invitation_accepted", true) // Only show participants who accepted invitation
            ->get();
        
        // Sanitize data - exclude sensitive information
        return $teams->map(function($team) {
            return [
                'id' => $team->id,
                'team' => $team->team,
                'score' => $team->score,
                'lobby_code' => $team->lobby_code,
                'subject_id' => $team->subject_id,
                'team_leader' => $team->team_leader,
                'members' => $team->members, // Include members for display (already stored as JSON string)
                // Exclude sensitive fields: team_leader_email, student_number, contact_number, etc.
            ];
        });
    }

    function moveFileToPublic($file, $folder)
    {
        $fileName = $file->hashName();
        $file->move(public_path("storage/$folder"), $fileName);
        return "$folder/$fileName";
    }

    // public function store(Request $request)
    // {
    //     //

    //     $validator = Validator::make($request->all(), [
    //         // 'team' => 'required|string|max:255',

    //         'validStudentId' => 'nullable|file|mimes:jpg,jpeg,png,pdf|max:2048',
    //         'signedConsentForm' => 'nullable|file|mimes:jpg,jpeg,png,pdf|max:2048',
    //         'registrationForm' => 'nullable|file|mimes:jpg,jpeg,png,pdf|max:2048',
    //     ]);

    //     if ($validator->fails()) {
    //         return response()->json([
    //             'errors' => $validator->errors(),
    //         ], 422);
    //     }

    //     $lobby = Lobby::where("lobby_code", $request->input("lobbyCode"))->first();

    //     $subject = Subjects::where("subject_name", $request->input("subject"))
    //         ->where("lobby_id", $lobby->id)->first();



    //     $id = $lobby->id;
    //     $subject_id = $subject->id;
    //     $team_count = Participants::where("lobby_code", $request->input("lobbyCode"))->count();
    //     $team = "Team " . $team_count + 1;
    //     // Store uploaded files if they exist
    //     $studentIdPath = $request->hasFile('validStudentId')
    //         ? $this->moveFileToPublic($request->file('validStudentId'), 'student_ids')
    //         : null;

    //     $consentFormPath = $request->hasFile('signedConsentForm')
    //         ?  $this->moveFileToPublic($request->file('signedConsentForm'), 'consent_forms')
    //         : null;

    //     $registrationFormPath = $request->hasFile('registrationForm')
    //         ?  $this->moveFileToPublic($request->file('registrationForm'), 'registration_forms')
    //         : null;

    //     // Process members
    //     $membersData = [];

    //     foreach ($request->input('members', []) as $index => $member) {
    //         $memberFiles = [];

    //         if ($request->hasFile("members.$index.studentId")) {
    //             $memberFiles['studentId'] =  $this->moveFileToPublic(
    //                 $request->file("members.$index.studentId"),
    //                 'members/student_ids'
    //             );
    //         }

    //         if ($request->hasFile("members.$index.registrationForm")) {
    //             $memberFiles['registrationForm'] =  $this->moveFileToPublic(
    //                 $request->file("members.$index.registrationForm"),
    //                 'members/registration_forms'
    //             );
    //         }

    //         if ($request->hasFile("members.$index.consentForm")) {
    //             $memberFiles['consentForm'] =  $this->moveFileToPublic(
    //                 $request->file("members.$index.consentForm"),
    //                 'members/consent_forms'
    //             );
    //         }

    //         $membersData[] = [
    //             'name' => $member['name'] ?? '',
    //             'studentNumber' => $member['studentNumber'] ?? '',
    //             'courseYear' => $member['courseYear'] ?? '',
    //             'requirements' => $memberFiles,
    //         ];
    //     }


    //     $user = Participants::create([
    //         // 'team' =>  $team,
    //         'team' => $request->input("teamName"),
    //         'members' => json_encode($membersData), // ✅ with file paths
    //         "lobby_code" => $request->input("lobbyCode"),
    //         "team_leader" => $request->input("team_leader"),
    //         "team_leader_email" => $request->input("team_leader_email"),
    //         "subject_id" =>  $subject_id,
    //         'joined_at' => now()->toDateTimeString(),
    //         "student_number" => $request->input("studentNumber"),
    //         "course_year" => $request->input("courseYear"),
    //         "contact_number" => $request->input("contactNumber"),
    //         "student_id" => $studentIdPath,
    //         "consent_form" => $registrationFormPath,
    //         "registration_form" => $registrationFormPath,
    //     ]);


    //     $team_id = $user->id;
    //     $name =  $team;
    //     $email = $request->team_leader_email;
    //     $subject = "Congratulations You're invited for a quiz event";
    //     $link = url("questionnaire/$id/$team_id/$subject_id");



    //     // Mail::to($email)->send(new EventInvitationMail($name, $email, $subject, $link));


    //     return response()->json([
    //         'message' => 'Student registered successfully',
    //         'user' => $user,
    //         'status' => "ok"
    //     ], 201);
    // }

public function store(Request $request)
{
    try {
        // ✅ 1. Validate input
        $validator = Validator::make($request->all(), [
            'validStudentId' => 'nullable|file|mimes:jpg,jpeg,png,pdf|max:2048',
            'signedConsentForm' => 'nullable|file|mimes:jpg,jpeg,png,pdf|max:2048',
            'registrationForm' => 'nullable|file|mimes:jpg,jpeg,png,pdf|max:2048',
            'team_leader_email' => 'required|email',
            'studentNumber' => 'required|string',
            'lobbyCode' => 'required|string',
            'subject' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        // ✅ 2. Find lobby and subject
        $lobby = Lobby::where("lobby_code", $request->input("lobbyCode"))->firstOrFail();
        $subject = Subjects::where("subject_name", $request->input("subject"))
            ->where("lobby_id", $lobby->id)
            ->firstOrFail();

        $id = $lobby->id;
        $subject_id = $subject->id;

        // ✅ 0. Check for duplicate registration WITHIN THE SAME LOBBY AND SUBJECT
        // A participant can register for different lobbies/subjects, but not duplicate within the same lobby/subject
        $existingParticipant = Participants::where('lobby_code', $request->input("lobbyCode"))
            ->where('subject_id', $subject_id)
            ->where(function($query) use ($request) {
                $query->where('team_leader_email', $request->input('team_leader_email'))
                      ->orWhere('student_number', $request->input('studentNumber'));
            })
            ->first();

        if ($existingParticipant) {
            return response()->json([
                'message' => 'You have already registered for this event.',
                'error' => 'Duplicate registration detected. Each email address and student number can only register once per lobby/subject combination.',
            ], 409); // 409 Conflict
        }

        // ✅ 3. Determine team name
        $team_count = Participants::where("lobby_code", $request->input("lobbyCode"))->count();
        $team = "Team " . ($team_count + 1);

        // ✅ 4. Handle file uploads safely
        $studentIdPath = $request->hasFile('validStudentId')
            ? $this->moveFileToPublic($request->file('validStudentId'), 'student_ids')
            : null;

        $consentFormPath = $request->hasFile('signedConsentForm')
            ? $this->moveFileToPublic($request->file('signedConsentForm'), 'consent_forms')
            : null;

        $registrationFormPath = $request->hasFile('registrationForm')
            ? $this->moveFileToPublic($request->file('registrationForm'), 'registration_forms')
            : null;

        // ✅ 5. Process members
        $membersData = [];
        foreach ($request->input('members', []) as $index => $member) {
            $memberFiles = [];

            if ($request->hasFile("members.$index.studentId")) {
                $memberFiles['studentId'] = $this->moveFileToPublic(
                    $request->file("members.$index.studentId"),
                    'members/student_ids'
                );
            }

            if ($request->hasFile("members.$index.registrationForm")) {
                $memberFiles['registrationForm'] = $this->moveFileToPublic(
                    $request->file("members.$index.registrationForm"),
                    'members/registration_forms'
                );
            }

            if ($request->hasFile("members.$index.consentForm")) {
                $memberFiles['consentForm'] = $this->moveFileToPublic(
                    $request->file("members.$index.consentForm"),
                    'members/consent_forms'
                );
            }

            $membersData[] = [
                'name' => $member['name'] ?? '',
                'studentNumber' => $member['studentNumber'] ?? '',
                'courseYear' => $member['courseYear'] ?? '',
                'requirements' => $memberFiles,
            ];
        }

        // ✅ 6. Save participant (invitation not yet accepted)
        $user = Participants::create([
            'team' => $request->input("team") ?? $team,
            'members' => json_encode($membersData),
            "lobby_code" => $request->input("lobbyCode"),
            "team_leader" => $request->input("team_leader"),
            "team_leader_email" => $request->input("team_leader_email"),
            "subject_id" => $subject_id,
            'joined_at' => now()->toDateTimeString(),
            "student_number" => $request->input("studentNumber"),
            "course_year" => $request->input("courseYear"),
            "contact_number" => $request->input("contactNumber"),
            "student_id" => $studentIdPath,
            "consent_form" => $consentFormPath,
            "registration_form" => $registrationFormPath,
            'invitation_accepted' => false, // Will be set to true when they click invitation link
        ]);

        // ✅ 7. Prepare email (optional)
        $team_id = $user->id;
        $name = $team;
        $email = $request->team_leader_email;
        $subjectLine = "Congratulations! You're invited for a quiz event";
        $link = url("questionnaire/$id/$team_id/$subject_id");

        // Mail::to($email)->send(new EventInvitationMail($name, $email, $subjectLine, $link));

        // ✅ 8. Return success (sanitized - exclude sensitive data)
        return response()->json([
            'message' => 'Student registered successfully',
            'user' => [
                'id' => $user->id,
                'team' => $user->team,
                'lobby_code' => $user->lobby_code,
                'subject_id' => $user->subject_id,
                // Exclude sensitive fields: team_leader_email, student_number, contact_number, etc.
            ],
            'status' => "ok"
        ], 201);

    } catch (\Exception $e) {
        // 🛑 Catch all runtime errors (DB, file, mail, etc.)
        return response()->json([
            'message' => 'An error occurred while processing your request.',
            'error' => $e->getMessage(),
            'line' => $e->getLine(),
            'file' => $e->getFile(),
        ], 500);
    }
}

    public function updateScore(string $id, $score, $ans, $question, $lobby_id, $question_id, $q_type, $prev_score_ui, $new_question)
    {

        
        // 1. Find the participant or fail
        $participant = Participants::where("id", $id)->firstOrFail();

        // 2. Add the new score to the existing one
        $newScore = $participant->score + $score;
        $prev_ans = $ans;
        // 3. Update the score


        // if ($score >= 0 && $q_type !== "short-answer") {
        //     $participant->score = $newScore;
        // }

        $participant->prev_answer = $prev_ans;
        $participant->prev_answer_correct = $score > 0 ? 1 : 0;
        //
        $participant->save();

        // PointsHistory::where("participant_id", $id)
        //     ->where("lobby_id", $lobby_id)
        //     ->where("question_id", $question_id)
        //  ->whereDate("created_at", Carbon::today()) // compares only the date
        //     ->delete();
        // Check if a record exists for this participant, question, and lobby today
        $record = PointsHistory::where("participant_id", $id)
            ->where("lobby_id", $lobby_id)
            ->where("question_id", $question_id)
            ->whereDate("created_at", Carbon::today())
            ->first();

        if ($record) {
            // Get old points before updating
            $oldPoints = $record->points ?? 0;
            
            // Update existing record: increment attempt count and update answer/points
            $record->attempt_answers = ($record->attempt_answers ?? 1) + 1;
            $record->answer = $ans;
            $record->points = $score;
            $record->question = $question;
            $record->save();
            
            // Update score only if this is not a short-answer or if score is positive
            if ($score >= 0 && $q_type !== "short-answer") {
                // Recalculate score: subtract old points and add new points
                // Ensure we're working with the latest participant score from database
                $participant->refresh();
                $participant->score = $participant->score - $oldPoints + $score;
                
                // Ensure score doesn't go below 0
                if ($participant->score < 0) {
                    $participant->score = 0;
                }
            }
        } else {
            // Create new record: first attempt
            if ($score >= 0 && $q_type !== "short-answer") {
                // Ensure we're working with the latest participant score from database
                $participant->refresh();
                $participant->score = $participant->score + $score;
                
                // Ensure score doesn't go below 0
                if ($participant->score < 0) {
                    $participant->score = 0;
                }
            }
            
            PointsHistory::create([
                "points" => $score,
                "question" => $question,
                "answer" => $ans,
                "participant_id" => $id,
                'lobby_id' => $lobby_id,
                'question_id' => $question_id,
                'attempt_answers' => 1
            ]);
        }
        $participant->save();


        // 4. Optional: return a response
        return response()->json([
            'message' => 'Score updated successfully.',
            'new_score' => $participant->score,
        ]);
        // try {


        //     // 1. Find the participant or fail
        //     $participant = Participants::where("id", $id)->firstOrFail();
        //     $sub_question = SubjectQuestion::where("id", $question_id)->first();
        //     $c_lobby = Lobby::where("id", $lobby_id)->first();
        //     // 2. Add the new score to the existing one
        //     $newScore = $participant->score + $score;
        //     $prev_score = $prev_score_ui == 0 ? $participant->score : $prev_score_ui;
        //     $d = "no";
        //     // if ($c_lobby->question_num == $curr_item) {
        //     if ($participant->prev_answer_correct == 1 && $score <= 0) {

        //         if ($participant->score <= 0) {
        //             $newScore = 0;
        //             $d = "s" . $newScore;
        //             $prev_score = $prev_score_ui;
        //         } else {
        //             $newScore  =  $participant->score  - $sub_question->points;
        //             $d = "swww" . $newScore;
        //             $prev_score =   $prev_score_ui;
        //         }
        //          $prev_score =  $newScore;
        //     } else {
        //         $newScore = $new_question == "yes" ? $score + $prev_score_ui : $participant->score + $score;
        //         $prev_score = $participant->score;
        //         $d = "YEs" . $score;
        //         // dd("Previous Score 1:", $prev_score);

        //     }
        //     // }else{
        //     //       $d = "YEs else" . $newScore;
        //     // }
        //     $prev_ans = $ans;
        //     // 3. Update the score


        //     if ($score >= 0 && $q_type !== "short-answer") {
        //         $participant->score = $newScore;
        //         $prev_score = $newScore;
        //         // dd("Previous Score 2:", $prev_score);

        //     }

        //     // if($score <=0 ){
        //     //       $prev_score = intval($prev_score_ui);
        //     // }
        //     $participant->prev_answer = $prev_ans;
        //     $participant->prev_answer_correct = $score > 0 ? 1 : 0;
        //     //
        //     $participant->save();

        //     // PointsHistory::where("participant_id", $id)
        //     //     ->where("lobby_id", $lobby_id)
        //     //     ->where("question_id", $question_id)
        //     //  ->whereDate("created_at", Carbon::today()) // compares only the date
        //     //     ->delete();
        //     $record = PointsHistory::where("participant_id", $id)
        //         ->where("lobby_id", $lobby_id)
        //         ->where("question_id", $question_id)
        //         ->whereDate("created_at", Carbon::today())
        //         ->first();

        //     if ($record) {
        //         $record->delete();
        //         // optional: return success response
        //     } else {

        //         if ($score >= 0 && $q_type !== "short-answer") {
        //             $participant->score = $newScore;
        //         }
        //     }
        //     $participant->save();
        //     PointsHistory::create([
        //         "points" =>  $score,
        //         "question" =>  $question,
        //         "answer" => $ans,
        //         "participant_id" => $id,
        //         'lobby_id' =>  $lobby_id,
        //         'question_id' => $question_id
        //     ]);


        //     // 4. Optional: return a response
        //     return response()->json([
        //         'message' => 'Score updated successfully.',
        //         'new_score' => $participant->score,
        //         'updated_score' => $newScore,
        //         'prev_score' => $prev_score,
        //         'cl' => $c_lobby->question_num,

        //         '$d' => $d
        //     ]);
        // } catch (QueryException $e) {
        //     // Catch database query errors (SQL, constraint violations, etc.)
        //     return response()->json([
        //         'success' => false,
        //         'message' => 'Database error occurred.',
        //         'error' => $e->getMessage(), // optional: remove in production
        //     ], 500);
        // } catch (\Exception $e) {
        //     // Catch any other general errors
        //     return response()->json([
        //         'success' => false,
        //         'message' => 'Unexpected error occurred.',
        //         'error' => $e->getMessage(),
        //     ], 500);
        // }
    }
    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
