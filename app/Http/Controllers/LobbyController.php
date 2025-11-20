<?php

namespace App\Http\Controllers;

use App\Events\QuizEvent;
use App\Models\Lobby;
use App\Models\LoobyManagement;
use App\Models\Subjects;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Inertia\Inertia;
use League\CommonMark\Delimiter\Bracket;

class LobbyController extends Controller
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
    public function changeState($id, $level, $subject_id)
    {
        Lobby::where('id', $id)->update([
            'start_timer' => 1
        ]);
        // Fetch the lobby again to get the updated model
        $lobby = Lobby::findOrFail($id);

        // Load questions
        $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($level) {
            $query->where('difficulty', $level);
        }])
            ->where('id', $subject_id)
            ->firstOrFail();


        // Use question_num to get current question (1-based index -> 0-based array)
        $current_question_index = $lobby->question_num - 1;
        $current_question = $questions->subjectsQuestions[0] ?? null;
        broadcast(new QuizEvent('general', $current_question, $lobby->question_num, $id, $level));

        return 1;
    }

    public function checkCode($code)
    {
        $lobby = Lobby::where('lobby_code', $code)->firstOrFail();

        $subject = Subjects::where('lobby_id', $lobby->id)->with("lobby")->get();

        return $subject;
    }



    public function showOverAllLeaderBoard($id, $subject_id)
    {
        Lobby::where('id', $id)->update([
            'start_timer' => 1
        ]);
        // Fetch the lobby again to get the updated model
        $lobby = Lobby::findOrFail($id);

        // Load questions

        $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($lobby) {
            $query->where('difficulty', $lobby->current_level);
        }])
            ->where('id', $subject_id)
            ->firstOrFail();

        // Use question_num to get current question (1-based index -> 0-based array)
        $current_question_index = $lobby->question_num - 1;
        $current_question = $questions->subjectsQuestions[0] ?? null;


        broadcast(new QuizEvent('over-all-leaderboard', $current_question, $lobby->question_num, $id, $lobby->current_level));
    }
    public function getLobby()
    {
        $lobbies = Lobby::where("archive", 0)->get();

        return $lobbies;
    }

    public function getOrganizerLobby()
    {
        // Get lobbies with their subjects for the authenticated user
        // This works for both Organizers (role 3) and Teachers (role 1)
        return Lobby::with('subjects')
            ->where('user_id', Auth::user()->id)
            ->where("archive", 0)
            ->get();
    }
    public function lobbyStatus($id)
    {
        return Lobby::where('id', $id)->get();
    }
    public function start($id)
    {
        Lobby::where('id', $id)->update([
            'started' => 1
        ]);
        $lobby = Lobby::find($id);

        broadcast(new QuizEvent('start-quiz', 1, 1, $id, $lobby->current_level));

        return 1;
    }
    public function gameLevel($id, $level, $subject_id)
    {
        $lobby = Lobby::where('id', $id)->update([
            'current_level' => $level,

        ]);
        // Fetch the lobby again to get the updated model
        $lobby = Lobby::findOrFail($id);

        // Load questions
        $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($level) {
            $query->where('difficulty', $level);
        }])
            ->where('id', $subject_id)
            ->firstOrFail();


        // Use question_num to get current question (1-based index -> 0-based array)
        $current_question_index = $lobby->question_num - 1;
        $current_question = $questions->subjectsQuestions[0] ?? null;

        if ($current_question == null) {
            return response()->json([
                "status" => 'error',
                "message" => 'No Question Available'
            ], 404);
        }
        //  dd($current_question);
        broadcast(new QuizEvent('level-changes', $current_question, $lobby->question_num, $id, $level));

        return 1;
    }
    public function startTimer($id, $subject_id)
    {
        Lobby::where('id', $id)->update([
            'start_timer' => 1
        ]);
        // Fetch the lobby again to get the updated model
        $lobby = Lobby::findOrFail($id);

        // Load questions

        $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($lobby) {
            $query->where('difficulty', $lobby->current_level);
        }])
            ->where('id', $subject_id)
            ->firstOrFail();

        // Use question_num to get current question (1-based index -> 0-based array)
        $current_question_index = $lobby->question_num - 1;
        
        // Get the questions collection and safely access the current question
        $subjectsQuestions = $questions->subjectsQuestions;
        
        if ($subjectsQuestions->isEmpty() || $current_question_index < 0 || $current_question_index >= $subjectsQuestions->count()) {
            return response()->json(['error' => 'Question not found'], 404);
        }
        
        $current_question = $subjectsQuestions[$current_question_index];

        // Broadcast the current question
        broadcast(new QuizEvent('timer-started', $current_question, $lobby->question_num, $id, $lobby->current_level));

        return 1;
    }
    public function revealOptions($id, $subject_id)
    {


        // First, update the lobby, then retrieve it
        Lobby::where('id', $id)->update([
            'reveal_options' => 1
        ]);

        // Fetch the lobby again to get the updated model
        $lobby = Lobby::findOrFail($id);

        // Load questions

        $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($lobby) {
            $query->where('difficulty', $lobby->current_level);
        }])
            ->where('id', $subject_id)
            ->firstOrFail();

        // Use question_num to get current question (1-based index -> 0-based array)
        $current_question_index = $lobby->question_num - 1;

        // Get the questions collection and safely access the current question
        $subjectsQuestions = $questions->subjectsQuestions;
        
        if ($subjectsQuestions->isEmpty() || !isset($subjectsQuestions[$current_question_index])) {
            return response()->json(['error' => 'Question not found'], 404);
        }
        
        $current_question = $subjectsQuestions[$current_question_index];

        // Broadcast the current question
        broadcast(new QuizEvent('options-revealed', $current_question, $lobby->question_num, $id, $lobby->current_level));

        return 1;
    }
    public function revealAnswer($id, $subject_id)
    {
        Lobby::where('id', $id)->update([
            'reveal_answer' => 1
        ]);

        // Fetch the lobby again to get the updated model
        $lobby = Lobby::findOrFail($id);

        // Load questions - match the query pattern from questionnaire route
        $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($lobby) {
            $query->where('difficulty', $lobby->current_level);
        }])
            ->where('id', $subject_id)
            ->firstOrFail();

        // Get the questions collection
        $subjectsQuestions = $questions->subjectsQuestions;
        
        if ($subjectsQuestions->isEmpty()) {
            return response()->json([
                'error' => 'No questions found',
                'details' => [
                    'subject_id' => $subject_id,
                    'current_level' => $lobby->current_level,
                    'question_num' => $lobby->question_num,
                    'total_questions' => 0
                ]
            ], 404);
        }
        
        // Try to get question at question_num index, fallback to first question if out of bounds
        // This matches the pattern used in questionnaire route and other methods
        $current_question_index = $lobby->question_num - 1;
        
        if ($current_question_index >= 0 && $current_question_index < $subjectsQuestions->count()) {
            $current_question = $subjectsQuestions[$current_question_index];
        } else {
            // Fallback to first question if index is out of bounds (matches questionnaire route behavior)
            $current_question = $subjectsQuestions[0];
        }

        // Broadcast the current question
        broadcast(new QuizEvent('answer-revealed', $current_question, $lobby->question_num, $id, $lobby->current_level));

        return 1;
    }
    public function revealLeaderboard($id, $subject_id, $items)
    {
        Lobby::where('id', $id)->update([
            'reveal_leaderboard' => 1
        ]);
        // Fetch the lobby again to get the updated model
        $lobby = Lobby::findOrFail($id);

        // Load questions

        $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($lobby) {
            $query->where('difficulty', $lobby->current_level);
        }])
            ->where('id', $subject_id)
            ->firstOrFail();

        // Use question_num to get current question (1-based index -> 0-based array)
        $current_question_index = $lobby->question_num - 1;
        
        // Get the questions collection and safely access the current question
        $subjectsQuestions = $questions->subjectsQuestions;
        $current_question = null;
        
        if (!$subjectsQuestions->isEmpty() && $current_question_index >= 0 && $current_question_index < $subjectsQuestions->count()) {
            $current_question = $subjectsQuestions[$current_question_index];
        }

        // Broadcast the current question

        if ($items == $lobby->question_num) {
            broadcast(new QuizEvent('finished', $current_question, $lobby->question_num, $id, $lobby->current_level));
            Lobby::where('id', $id)->update([
                'finished' => 1
            ]);
        } else {
            broadcast(new QuizEvent('leaderboard-revealed', $current_question, $lobby->question_num, $id, $lobby->current_level));
        }


        return 1;
    }
    public function getNewLevel($id)
    {
        $lobby = Lobby::findOrFail($id);

        return response()->json([
            'level' => $lobby->levels_finished,
        ], 200);
    }
    public function nextquestion($id, $subject_id)
    {
        DB::transaction(function () use ($id, $subject_id) {

            $lobby = Lobby::findOrFail($id);
            $next = $lobby->question_num + 1;
            // Update the question number
            $updated = Lobby::where('id', $id)->update([
                'question_num' => $next
            ]);

            // Only proceed if update was successful (i.e., affected 1 or more rows)
            if ($updated) {
                Lobby::where('id', $id)->update([
                    'start_timer' => '0',
                    'reveal_answer' => '0',
                    'reveal_leaderboard' => '0',
                    'reveal_options' => '0'
                ]);

                // Load questions

                $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($lobby) {
                    $query->where('difficulty', $lobby->current_level)
                        ->where("archive", 0);
                }])
                    ->where('id', $subject_id)
                    ->firstOrFail();
                // Use question_num to get current question (1-based index -> 0-based array)
                $current_question_index = $next - 1;
                $current_question = $questions->subjectsQuestions[0] ?? null;


                if ($current_question == null) {
                    Lobby::where('id', $id)->update([
                        'levels_finished' => $lobby->levels_finished . '-' . $lobby->current_level  . '-',
                    ]);

                    broadcast(new QuizEvent('switch-new-level', null, null, $id, $lobby->current_level));
                } else {
                    broadcast(new QuizEvent('', $current_question, $next, $id, $lobby->current_level));
                }
                // $current_question = $questions->subjectsQuestions ?? null;
                // dd($current_question);
                // Broadcast the current question

            } else {
                throw new \Exception("Failed to update question number for lobby ID: $id");
            }
        });
    }
    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'code' => 'required|string|max:255|unique:lobby,lobby_code',
        ], [
            'code.unique' => 'This lobby code is already in use. Please choose a different code.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors(),
            ], 422);
        }

        // Check if lobby code already exists (additional safety check)
        $existingLobby = Lobby::where('lobby_code', $request->input('code'))->first();
        if ($existingLobby) {
            return response()->json([
                'errors' => [
                    'code' => ['This lobby code is already in use by another organizer. Please choose a different code.']
                ],
            ], 422);
        }

        // Convert to proper format for MySQL while keeping the organizer's timezone
        $startDateInput = $request->input('date');
        $startDate = Carbon::parse($startDateInput, config('app.timezone'))
            ->setTimezone(config('app.timezone'))
            ->format('Y-m-d H:i:s');
        
        try {
            $lobby = Lobby::create([
                'name' => $request->input('name'),
                'lobby_code' => $request->input('code'),
                'start_date' => $startDate,
                'user_id' => Auth::user()->id
            ]);
        } catch (\Illuminate\Database\QueryException $e) {
            // Handle unique constraint violation
            if ($e->getCode() === '23000') {
                return response()->json([
                    'errors' => [
                        'code' => ['This lobby code is already in use. Please choose a different code.']
                    ],
                ], 422);
            }
            throw $e;
        }

        LoobyManagement::create([
            "user_id" => Auth::id(),
            "lobby_id" => $lobby->id,
            "action" => 0
        ]);

        return Inertia::render('OrganizerLobby', [
            'lobby' => Lobby::where("user_id", Auth::user()->id)->where("archive", 0)->get()
        ]);
    }

    public function quickCreate(Request $request)
    {
        // Auto-generate lobby code
        do {
            $lobbyCode = mt_rand(100000, 999999);
        } while (Lobby::where('lobby_code', $lobbyCode)->exists());

        // Create lobby with default name
        $lobbyName = $request->input('name', 'New Quiz ' . date('Y-m-d H:i'));
        
        try {
            $lobby = Lobby::create([
                'name' => $lobbyName,
                'lobby_code' => (string)$lobbyCode,
                'start_date' => now(),
                'user_id' => Auth::id(),
            ]);

            LoobyManagement::create([
                "user_id" => Auth::id(),
                "lobby_id" => $lobby->id,
                "action" => 0
            ]);

            // Automatically create a default subject
            $subject = Subjects::create([
                'subject_name' => 'Main Quiz',
                'lobby_id' => $lobby->id,
                'quiz_title' => $lobbyName,
                'start_date' => now(),
            ]);

            // Return the subject_id so frontend can redirect
            return response()->json([
                'success' => true,
                'message' => 'Quiz created successfully',
                'lobby' => [
                    'id' => $lobby->id,
                    'name' => $lobby->name,
                    'lobby_code' => $lobby->lobby_code,
                ],
                'subject' => [
                    'id' => $subject->id,
                    'name' => $subject->subject_name,
                ]
            ], 201);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to create quiz: ' . $e->getMessage(),
            ], 500);
        }
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
        // Verify the lobby belongs to the current user
        $lobby = Lobby::findOrFail($id);
        
        if ($lobby->user_id !== Auth::id()) {
            abort(403, 'You are not authorized to update this lobby.');
        }

        // Validate with unique check (excluding current lobby)
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'code' => 'required|string|max:255|unique:lobby,lobby_code,' . $id,
        ], [
            'code.unique' => 'This lobby code is already in use. Please choose a different code.',
        ]);

        if ($validator->fails()) {
            return back()->withErrors($validator->errors());
        }

        // Additional check for existing lobby code
        $existingLobby = Lobby::where('lobby_code', $request->code)
            ->where('id', '!=', $id)
            ->first();
            
        if ($existingLobby) {
            return back()->withErrors([
                'code' => 'This lobby code is already in use by another organizer. Please choose a different code.'
            ]);
        }

        try {
            $lobby->name = $request->name;
            $lobby->lobby_code = $request->code;
            $lobby->save();
        } catch (\Illuminate\Database\QueryException $e) {
            // Handle unique constraint violation
            if ($e->getCode() === '23000') {
                return back()->withErrors([
                    'code' => 'This lobby code is already in use. Please choose a different code.'
                ]);
            }
            throw $e;
        }

        LoobyManagement::create([
            "user_id" => Auth::id(),
            "lobby_id" => $lobby->id,
            "action" => 1
        ]);
        return redirect()->route('organizerLobby')
            ->with('success', 'Lobby Updated');
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {


        $lobby = Lobby::findOrFail($id);
        LoobyManagement::create([
            "user_id" => Auth::id(),
            "lobby_id" => $lobby->id,
            "action" => 2
        ]);


        $lobby->archive = 1;
        $lobby->save();

        // return redirect()->route('organizerLobby')
        //     ->with('success', 'Lobby deleted successfully');
        return Inertia::render('OrganizerLobby', [
            'lobby' => Lobby::where("user_id", Auth::user()->id)->where("archive", 0)->get()
        ]);
        //
    }
}
