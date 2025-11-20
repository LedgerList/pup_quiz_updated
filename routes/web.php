<?php

use App\Events\QuizEvent;
use App\Http\Controllers\EmailController;
use App\Http\Controllers\ProfileController;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;
use App\Http\Controllers\StudentRegistrationController;
use App\Http\Controllers\MemberRegistrationController;
use App\Http\Controllers\TeacherRegistrationController;
use App\Http\Controllers\OrganizerRegistrationController;
use App\Http\Controllers\QuizController;
use App\Http\Controllers\LiveQuizSessionController;
use App\Http\Controllers\LobbyController;
use App\Http\Controllers\LoginLogsController;
use App\Http\Controllers\ParticipantController;
use App\Http\Controllers\QuizEventController;
use App\Http\Controllers\ReportController;
use App\Http\Controllers\SessionLogsController;
use App\Http\Controllers\TieBreakerController;
use App\Http\Controllers\SubjectController;
use App\Http\Controllers\SubjectQuestionController;
use App\Models\EndedEvent;
use App\Models\LeaderboardLog;
use App\Models\Lobby;
use App\Models\LoobyManagement;
use App\Models\Participants;
use App\Models\PreRegistration;
use App\Models\QuizManagement;
use App\Models\SessionLogs;
use App\Models\SubjectQuestion;
use App\Models\Subjects;
use Carbon\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
//Registration Controller Routes
Route::post('/register-student', [StudentRegistrationController::class, 'register']);
Route::post('/register-member', [MemberRegistrationController::class, 'register']);
Route::post('/register-teacher', [TeacherRegistrationController::class, 'register']);
Route::post('/register-organizer', [OrganizerRegistrationController::class, 'register']);

//Login Routes
Route::get('/login', function () {
    return Inertia::render('Welcome', [
        'canLogin' => Route::has('login'),
        'canRegister' => Route::has('register'),
        'laravelVersion' => Application::VERSION,
        'phpVersion' => PHP_VERSION,
    ]);
});


Route::post('/otp-login', [EmailController::class, 'sendOtp'])->name("otp-login");
Route::post('/resendOTP', [EmailController::class, 'resendOTP']);
Route::post('/verifyOtp', [EmailController::class, 'verifyOtp'])->name("verifyOtp");
Route::post('/send-registration-otp', [EmailController::class, 'sendRegistrationOtp'])->name("send-registration-otp");
//Views Routes
Route::get('/dashboard', function (Request $request) {

    // dd(Auth::id());

    if (Auth::id()) {
        try {
            SessionLogs::create([
                'user_id'    => Auth::id(),
                'ip_address' => $request->ip(),
            ]);
        } catch (\Throwable $e) {
            // Log the error for debugging

            // Optionally show it immediately (for local debugging only)
            dd($e->getMessage());
        }
    }


    // Only redirect Organizers (role 3) to organizerLobby, Teachers (role 1) should see regular Dashboard
    if (Auth::user()->role == 3) {
        return redirect()->route('organizerLobby');
    }
    return Inertia::render('Dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');
Route::get('/explore', function (Request $request) {
    return Inertia::render('Explore', [
        'subject_id' => $request->query('subject_id')
    ]);
})->middleware(['auth', 'verified'])->name('explore');

Route::get('/session-history', function () {
    try {
        $logs = SessionLogs::with('user')
            ->where("user_id", Auth::id())
            ->orderBy('created_at', 'desc')
            ->get()
            ->map(function ($log) {
                return [
                    'id' => $log->id,
                    'user_id' => $log->user_id,
                    'user_name' => $log->user->name ?? 'Unknown',
                    'ip_address' => $log->ip_address ?? 'N/A',
                    'created_at' => $log->created_at ? $log->created_at->toISOString() : null,
                    'logout_timestamp' => $log->logout_timestamp ? $log->logout_timestamp->toISOString() : null,
                ];
            });

        return Inertia::render('SessionHistory', [
            "logs" => $logs
        ]);
    } catch (\Exception $e) {
        \Log::error('Error fetching session history: ' . $e->getMessage());
        return Inertia::render('SessionHistory', [
            "logs" => []
        ]);
    }
})->middleware(['auth', 'verified'])->name('session-history');
Route::get('/lobby-management', function () {
    // Only allow organizers (role 3) to access this page
    if (Auth::user()->role !== 3) {
        return redirect()->route('dashboard')->with('error', 'Access denied. This page is only available for organizers.');
    }
    
    $logs = LoobyManagement::with('lobby')->where("user_id", Auth::id())->get();
    $lobbies = Lobby::where("user_id", Auth::id())->get();

    return Inertia::render('LobbyManagement', [
        "logs" => $logs,
        "lobbies" => $lobbies
    ]);
})->middleware(['auth', 'verified'])->name('lobby-management');
Route::get('/participant-management', function () {
    return Inertia::render('ParticipantManagement');
})->middleware(['auth', 'verified'])->name('participant-management');
Route::get('/quiz-management', function () {
    $logs = QuizManagement::with(['question.subject.lobby'])
        ->where("user_id", Auth::id())
        ->latest()
        ->get();
    $lobbies = Lobby::where("user_id", Auth::id())->get();

    return Inertia::render('QuizManagement', [
        "logs" => $logs,
        "lobbies" => $lobbies
    ]);
})->middleware(['auth', 'verified'])->name('quiz-management');

Route::get('/getLobbyCategory', function () {

    $lobbies = Lobby::with('subjects')->where("user_id", Auth::id())->get();

    // $lobbies = Lobby::with('subjects')
    //     ->where('lobby_code', $lobbyCode)
    //     ->where('archive', 0)
    //     ->get();

    // // $controller = app(QuizEventController::class);
    // // $state = $controller->closeEvent($lobbies[0]->id,0);
    return response()->json(
        [
            "lobbies" => $lobbies
        ]

    );
})->name('getLobbyCategory');

Route::get('/getLobbySubjects/{lobby_id}', function ($lobby_id) {

    $subjects = Subjects::where('lobby_id', $lobby_id)
        ->where('archive', 0)
        ->get();
    return response()->json(
        [
            "subjects" => $subjects
        ]

    );
})->name('getLobbySubjects');


Route::get('/scoring', function () {
    $logs = LeaderboardLog::with('participant')->where("user_id", Auth::id())->get();
    $lobbies = Lobby::where("user_id", Auth::id())->get();
    return Inertia::render('Scoring', [
        "logs" => $logs,
        "lobbies" => $lobbies
    ]);
})->middleware(['auth', 'verified'])->name('scoring');

Route::get('/', function () {

    return Inertia::render('Home');
})->name('home');
Route::get('/teacher', function () {
    return Inertia::render('Teacher');
})->name('teacher');
Route::get('/quizLobby', function () {
    return Inertia::render('QuizLobby');
})->name('quizLobby');
Route::get('/student', function () {
    return Inertia::render('Student');
})->name('student');

Route::get('/participant', function () {
    return Inertia::render('Participant');
})->name('participant');
Route::get('/host', function () {
    return Inertia::render('Host');
})->name('host');
Route::get('/category', function () {
    return Inertia::render('Category');
})->name('category');
Route::get('/pre-registration', function () {
    // Only allow organizers (role 3) to access this page
    if (Auth::user()->role !== 3) {
        return redirect()->route('dashboard')->with('error', 'Access denied. This page is only available for organizers.');
    }
    
    try {
        $logs = PreRegistration::with('lobby', 'participant')->where("user_id", Auth::user()->id)->get();
        // Make hidden fields visible for the participant relationship
        $logs->each(function ($log) {
            if ($log->participant) {
                $log->participant->makeVisible(['team_leader_email', 'contact_number', 'student_number', 'student_id', 'consent_form', 'registration_form', 'members']);
            }
        });
        $lobbies = Lobby::where("user_id", Auth::id())->get();
    } catch (\Exception $e) {
        return response()->json([
            'success' => false,
            'message' => 'Something went wrong during registration.',
            'error' => $e->getMessage(),
        ], 500);
    }
    return Inertia::render('PreRegistrationLogs', [
        "logs" => $logs,
        "lobbies" => $lobbies
    ]);
})->middleware(['auth', 'verified'])->name('pre-registration');
Route::get('/manage-pre-registration/{lobby_code}', function ($lobby_code) {
    $pre_registration =  Participants::where("lobby_code", $lobby_code)
        ->where('is_approved', 0)
        ->get()
        ->makeVisible(['team_leader', 'team_leader_email', 'student_number', 'contact_number', 'student_id', 'consent_form', 'registration_form', 'members']);
    $lobby =  Lobby::where("lobby_code", $lobby_code)->first();
    return Inertia::render('ManagePreRegistration', [
        "lobby" => $lobby,
        "pre_registration" => $pre_registration
    ]);
})->name('manage-pre-registration');

Route::post('/manage-pre-registration', [ParticipantController::class, "managePreRegistration"])->name('manage-pre-registration');
// Route::get('/lobby/{id}/{subject_id}/{team_id}', function ($id, $subject_id,$team_id) {
//     $subject = Subjects::where('id', $subject_id)
//     ->get();
//     return Inertia::render('Lobby', ['id' => $id, 'subject_id' => $subject_id, 'subject' => $subject,'team_id'=>$team_id]);
// })->name('lobby');


Route::get('/lobby', function () {
    if (Auth::check()) {
        // Only redirect organizers (role 3) to organizerLobby
        if (Auth::user()->role === 3) {
            return redirect()->route('organizerLobby');
        }
        // Teachers and other roles go to their dashboard
        return redirect()->route('dashboard');
    }
    return redirect()->route('login');
})->name('lobby.index');

Route::get('/organizerLobby', function () {
    // Only allow organizers (role 3) to access this page
    if (Auth::user()->role !== 3) {
        return redirect()->route('dashboard')->with('error', 'Access denied. This page is only available for organizers.');
    }
    return Inertia::render('OrganizerLobby');
})->middleware(['auth', 'verified'])->name('organizerLobby');

Route::get('/audit-trails', function () {
    $userId = Auth::id();
    $allLogs = [];
    
    // Get organizer's lobbies
    $organizerLobbies = Lobby::where('user_id', $userId)->pluck('id')->toArray();
    
    // Get Session History Logs (only for the organizer)
    $sessionLogs = SessionLogs::where('user_id', $userId)->get();
    foreach ($sessionLogs as $log) {
        $user = \App\Models\User::find($log->user_id);
        $allLogs[] = [
            'id' => 'session-' . $log->id,
            'type' => 'Session History',
            'user_name' => $user->name ?? 'Unknown',
            'action' => $log->logout_timestamp ? 'Logout' : 'Login',
            'description' => $log->logout_timestamp 
                ? "User logged out" 
                : "User logged in from " . ($log->ip_address ?? 'Unknown IP'),
            'ip_address' => $log->ip_address ?? 'N/A',
            'timestamp' => $log->logout_timestamp ?? $log->created_at,
            'lobby_id' => null,
            'lobby_name' => null
        ];
    }
    
    // Get Lobby Management Logs
    $lobbyLogs = LoobyManagement::with('lobby')->where('user_id', $userId)->get();
    foreach ($lobbyLogs as $log) {
        $user = \App\Models\User::find($log->user_id);
        $actionMap = [0 => 'Create', 1 => 'Edit', 2 => 'Delete'];
        $lobbyName = $log->lobby?->name ?? 'Unknown';
        $action = $actionMap[$log->action] ?? 'modified';
        $allLogs[] = [
            'id' => 'lobby-' . $log->id,
            'type' => 'Lobby Management',
            'user_name' => $user->name ?? 'Unknown',
            'action' => $actionMap[$log->action] ?? 'Unknown',
            'description' => "Lobby '{$lobbyName}' was {$action}",
            'ip_address' => 'N/A',
            'timestamp' => $log->created_at,
            'lobby_id' => $log->lobby_id,
            'lobby_name' => $lobbyName
        ];
    }
    
    // Get Quiz Management Logs (all logs for questions in organizer's lobbies)
    $quizLogs = QuizManagement::with(['question.subject.lobby'])
        ->whereHas('question.subject.lobby', function($q) use ($organizerLobbies) {
            $q->whereIn('id', $organizerLobbies);
        })
        ->get();
    foreach ($quizLogs as $log) {
        $user = \App\Models\User::find($log->user_id);
        $actionMap = [0 => 'Create', 1 => 'Edit', 2 => 'Delete'];
        $question = $log->question;
        $lobby = $question->subject->lobby ?? null;
        $questionText = $question->question ?? 'Unknown';
        $action = $actionMap[$log->action] ?? 'modified';
        if ($lobby && in_array($lobby->id, $organizerLobbies)) {
            $allLogs[] = [
                'id' => 'quiz-' . $log->id,
                'type' => 'Quiz Management',
            'user_name' => $user->name ?? 'Unknown',
            'action' => $actionMap[$log->action] ?? 'Unknown',
            'description' => "Question '{$questionText}' was {$action}",
            'ip_address' => 'N/A',
            'timestamp' => $log->created_at,
            'lobby_id' => $lobby?->id ?? null,
            'lobby_name' => $lobby?->name ?? null
            ];
        }
    }
    
    // Get Scoring/Results Logs (all logs for participants in organizer's lobbies)
    $scoringLogs = LeaderboardLog::with(['participant.subject.lobby'])
        ->whereHas('participant.subject.lobby', function($q) use ($organizerLobbies) {
            $q->whereIn('id', $organizerLobbies);
        })
        ->get();
    foreach ($scoringLogs as $log) {
        $user = \App\Models\User::find($log->user_id);
        $participant = $log->participant;
        $lobby = $participant->subject->lobby ?? null;
        $teamName = $participant->team ?? 'Unknown';
        if ($lobby && in_array($lobby->id, $organizerLobbies)) {
            $allLogs[] = [
                'id' => 'scoring-' . $log->id,
                'type' => 'Scoring / Results',
            'user_name' => $user->name ?? 'Unknown',
            'action' => 'Score Recorded',
            'description' => "Team '{$teamName}' scored {$log->total_score} points (Rank: {$log->place})",
            'ip_address' => 'N/A',
            'timestamp' => $log->created_at,
            'lobby_id' => $lobby?->id ?? null,
            'lobby_name' => $lobby?->name ?? null
            ];
        }
    }
    
    // Get Pre-Registration Logs (all logs for organizer's lobbies)
    $preRegLogs = PreRegistration::with(['lobby', 'participant'])
        ->whereIn('lobby_id', $organizerLobbies)
        ->get();
    foreach ($preRegLogs as $log) {
        $user = \App\Models\User::find($log->user_id);
        $statusMap = [1 => 'Rejected', 2 => 'Approved'];
        $teamName = $log->participant?->team ?? 'Unknown';
        $status = $statusMap[$log->status] ?? 'processed';
        $lobbyName = $log->lobby?->name ?? 'Unknown';
        $allLogs[] = [
            'id' => 'prereg-' . $log->id,
            'type' => 'Pre-Registration Logs',
            'user_name' => $user->name ?? 'Unknown',
            'action' => $statusMap[$log->status] ?? 'Pending',
            'description' => "Team '{$teamName}' registration was {$status}",
            'ip_address' => 'N/A',
            'timestamp' => $log->created_at,
            'lobby_id' => $log->lobby_id,
            'lobby_name' => $lobbyName
        ];
    }
    
    // Get Question Statistics (PointsHistory for questions in organizer's lobbies)
    $questionStats = \App\Models\PointsHistory::with(['question.subject.lobby'])
        ->whereHas('question.subject.lobby', function($q) use ($organizerLobbies) {
            $q->whereIn('id', $organizerLobbies);
        })
        ->get()
        ->groupBy(function($item) {
            return $item->question->subject->lobby_id ?? 0;
        });
    
    foreach ($questionStats as $lobbyId => $stats) {
        if ($lobbyId && in_array($lobbyId, $organizerLobbies)) {
            $lobby = $stats->first()->question->subject->lobby ?? null;
            $lobbyName = $lobby ? $lobby->name : 'Unknown Lobby';
            $allLogs[] = [
                'id' => 'stats-' . $lobbyId,
                'type' => 'Question Statistics',
                'user_name' => Auth::user()->name,
                'action' => 'Active',
                'description' => "Question statistics updated for {$lobbyName} ({$stats->count()} records)",
                'ip_address' => 'N/A',
                'timestamp' => $stats->max('created_at') ? $stats->max('created_at') : now(),
                'lobby_id' => $lobbyId,
                'lobby_name' => $lobby ? $lobby->name : null
            ];
        }
    }
    
    // Sort by timestamp (newest first)
    usort($allLogs, function($a, $b) {
        return strtotime($b['timestamp']) - strtotime($a['timestamp']);
    });
    
    $lobbies = Lobby::where('user_id', $userId)->get();
    
    return Inertia::render('AuditTrails', [
        'allLogs' => $allLogs,
        'lobbies' => $lobbies
    ]);
})->middleware(['auth', 'verified'])->name('audit-trails');
Route::get('/lobbyCategory/{id}', function ($lobbyCode) {


    $lobbies = Lobby::with('subjects')
        ->where('lobby_code', $lobbyCode)
        ->where('archive', 0)
        ->get();

    // $controller = app(QuizEventController::class);
    // $state = $controller->closeEvent($lobbies[0]->id,0);
    return Inertia::render('LobbyCategory', [
        'lobbies' => $lobbies,
        'id' =>   $lobbies[0]->id
    ]);
})->name('lobbyCategory');




Route::get('/subjectQuestionForm/{subjectId}', function ($subjectId) {


    $questions = Subjects::with('subjectsQuestions')
        ->where('id', $subjectId)
        ->get();

    return Inertia::render('SubjectQuestionForm', [
        'subject_questions' => $questions,
        'subjectId' => $subjectId,


    ]);
})->name('subjectQuestionForm');


Route::get('/quizmaster', function () {
    return Inertia::render('QuizMaster');
})->name('quizMaster');
Route::get('/getStarted', function () {
    return Inertia::render('GetStarted');
})->name('getStarted');
Route::get('/organizer', function () {
    return Inertia::render('Organizer');
})->name('organizer');
Route::get('/mylibrary', function () {
    return Inertia::render('MyLibrary');
})->name('mylibrary');
Route::get('/templates', function () {
    return Inertia::render('Templates');
})->name('templates');
Route::get('/createquiz', function (Request $request) {
    return Inertia::render('CreateQuiz', [
        'subject_id' => $request->query('subject_id')
    ]);
})->name('createquiz');
Route::get('/settings', function () {
    return Inertia::render('Settings');
})->name('settings');
Route::get('/privacy', function () {
    return Inertia::render('Privacy');
})->name('privacy');
Route::get('/myperformance', function () {
    $userId = Auth::id();
    
    // Get actual quiz attempts for the user
    $quizAttempts = \App\Models\QuizAttempt::where('user_id', $userId)
        ->with(['quiz'])
        ->where('status', 'completed') // Only show completed attempts
        ->orderBy('end_time', 'desc')
        ->get()
        ->map(function ($attempt) {
            return [
                'id' => $attempt->id,
                'quiz_id' => $attempt->quiz_id,
                'quiz_title' => $attempt->quiz->title ?? 'Unknown Quiz',
                'quiz_code' => $attempt->quiz->code ?? 'N/A',
                'category' => $attempt->quiz->category ?? 'General',
                'score' => $attempt->score ?? 0,
                'date_taken' => $attempt->end_time ? $attempt->end_time->format('M d, Y') : ($attempt->created_at ? $attempt->created_at->format('M d, Y') : 'N/A'),
                'type' => 'Teacher Quiz', // You can customize this based on quiz type
                'status' => $attempt->status,
            ];
        });

    return Inertia::render('MyPerformance', [
        'quizAttempts' => $quizAttempts
    ]);
})->middleware(['auth', 'verified'])->name('myperformance');
Route::get('/myquizzes', function () {
    return Inertia::render('MyQuizzes');
})->name('myquizzes');
Route::get('/member', function () {
    return Inertia::render('Member');
})->name('member');
Route::get('/chairman', function () {
    return Inertia::render('Chairman');
})->name('chairman');

Route::get('/statistics',  function () {
    $categories = Subjects::whereHas('lobby', function ($query) {
        $query->where('user_id', Auth::id());
    })->get();
    $questions = $categories->flatMap(function ($subject) {
        return $subject->subjectsQuestions;
    });

    $topLobbyCategory = DB::table('points_history')
        ->join('subject_questions', 'subject_questions.id', '=', 'points_history.question_id')
        ->join('subjects', 'subjects.id', '=', 'subject_questions.subject_id')
        ->join('lobby', 'lobby.id', '=', 'points_history.lobby_id')
        ->select(
            'lobby.name',
            'subjects.id as subject_id',
            'subjects.subject_name',
            'subject_questions.difficulty',
            DB::raw('SUM(points_history.points) as total_points'),
            DB::raw('COUNT(subject_questions.id) as total_questions')
        )
        ->where('points_history.points', '>', 0)
        ->where('lobby.user_id', Auth::user()->id)
        ->groupBy(
            'subjects.id',
            'subjects.subject_name',
            'lobby.name',
            'subject_questions.difficulty'
        )
        ->orderByDesc('total_points')
        ->limit(1)
        ->first();

    $lobbies = Lobby::where("user_id", Auth::id())->get();

    return Inertia::render('QuizStatisticsDashboard', [
        'questions' => $questions,
        'categories' => $categories,
        'topLobbyCategory' => $topLobbyCategory,
        'lobbies' => $lobbies
    ]);
})->name('statistics');

Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    //Quiz Controllers Routes
    Route::get('/quizzes/create', [QuizController::class, 'create'])->name('quizzes.create');

    Route::post('/quizzes', [QuizController::class, 'store'])->name('quizzes.store');
    Route::get('/quizzes/my', [QuizController::class, 'index'])->name('quizzes.my');
    Route::get('/quizzes/myj', [QuizController::class, 'indexj'])->name('quizzes.joined');
    Route::get('/quizzes/{quiz}', [QuizController::class, 'show'])->name('quizzes.show');
    Route::post('/quizzes/join', [QuizController::class, 'join'])->middleware(['auth', 'verified'])->name('quizzes.join');
    Route::get('/quizzes/{quiz}/edit', [QuizController::class, 'edit'])->name('quizzes.edit');
    Route::post('/quizzes/{quiz}', [QuizController::class, 'update'])->name('quizzes.update');
    Route::get('/quizzes/{quiz}/start', [QuizController::class, 'start'])->name('quizzes.start');
    Route::get('/quizzes/{quiz}/start', [QuizController::class, 'start'])->name('quiz.start');
    Route::get('/quizzes/{quiz}/starting', [QuizController::class, 'starting'])->name('quizzes.starting');
});
Route::post('/question/edit', [QuizController::class, 'updateQuestion'])->name('question.edit');
Route::delete('/question/delete', [QuizController::class, 'deleteQuestion'])->name('question.delete');
Route::get('/quizzes/{quiz}/live', function (App\Models\Quiz $quiz) {
    $quiz->load(['questions.options']);
    return Inertia::render('LiveQuizSession', ['quiz' => $quiz]);
})->name('quizzes.live_session');
require __DIR__ . '/auth.php';

Route::post('/participant', [ParticipantController::class, 'store'])->name('participant');
Route::post('/participant/verify-team', [ParticipantController::class, 'verify'])->name('participant.verify-team');


Route::get('/lobby/{id}/{subject_id}/{team_id?}', function ($id, $subject_id, $team_id = 'organizer') {
    $subject = Subjects::findOrFail($subject_id);
    
    if ($team_id != "organizer") {
        // This is an invitation link - mark invitation as accepted
        $team = Participants::findOrFail($team_id);
        
        // Verify the team belongs to this lobby and subject
        $lobby = Lobby::where("id", $id)->where("archive", 0)->firstOrFail();
        if ($team->lobby_code !== $lobby->lobby_code) {
            abort(403, 'Invalid invitation link');
        }
        
        // Mark invitation as accepted
        $team->subject_id = $subject_id;
        $team->invitation_accepted = true;
        $team->invitation_accepted_at = now();
        $team->save();
    }
   $event_status = EndedEvent::where('lobby_id', $id)
    ->whereDate('created_at', Carbon::today('Asia/Manila'))
    ->first();



    // $lobby = Lobby::findOrFail($id);
    $lobby = Lobby::where("id", $id)
        ->where("archive", 0)
        ->firstOrFail();

    // Check if subject start_date is in the future - show EventReminder
    // Subject start_date takes precedence over lobby start_date
    $startDateToCheck = $subject->start_date ?? $lobby->start_date;
    
    if ($startDateToCheck) {
        $now = Carbon::now('Asia/Manila');
        $start = Carbon::parse($startDateToCheck)->setTimezone('Asia/Manila');
        
        if ($now->lessThan($start)) {
            // Pass the start_date as ISO string for frontend countdown
            return Inertia::render("EventReminder", [
                "start_date" => $start->toIso8601String(),
                "lobby_name" => $lobby->name ?? "Quiz Event"
            ]);
        }
    }

    $current_question = $lobby->question_num;

    if ($lobby->started == 1) {

        if (Auth::user()) {
            broadcast(new QuizEvent('start-quiz', $current_question, $lobby->question_num, $id, $lobby->current_level));
        }

        return redirect()->route('questionnaire', [
            'id' => $id,
            'team_id' => $team_id,
            'subject_id' => $subject_id,

        ]);
    }
    return Inertia::render('Lobby', [
        'id' => $id,
        'subject_id' => $subject_id,
        'subject' => $subject,
        'team_id' => $team_id,
        'show_leaderboard_report_btn'=>   $event_status ? 1: 0
    ]);
})->name('lobby');



Route::get('/questionnaire/{id}/{team_id}/{subject_id}', function ($id, $team_id, $subject_id) {
    // Mark invitation as accepted when accessing questionnaire via invitation link
    if ($team_id != "organizer") {
        $team = Participants::find($team_id);
        if ($team && !$team->invitation_accepted) {
            // Verify the team belongs to this lobby
            $lobby = Lobby::where("id", $id)->where("archive", 0)->first();
            if ($lobby && $team->lobby_code === $lobby->lobby_code) {
                $team->subject_id = $subject_id;
                $team->invitation_accepted = true;
                $team->invitation_accepted_at = now();
                $team->save();
            }
        }
    }

    $subject = Subjects::where("id", $subject_id)->first();
    $now = Carbon::now('Asia/Manila');

    $lobby_event_now = Lobby::where("id", $id)
        ->where("archive", 0)
        ->firstOrFail();

    // Check if event start_date is in the future - show EventReminder
    if ($lobby_event_now->start_date) {
        $start = Carbon::parse($lobby_event_now->start_date)->setTimezone('Asia/Manila');
        
        if ($now->lessThan($start)) {
            $diff = $now->diff($start); // DateInterval object

            $days = $diff->d;
            $hours = $diff->h;
            $minutes = $diff->i;

            $message = "Event will start in {$days}d {$hours}h {$minutes}m";

            return Inertia::render("EventReminder", [
                "msg" => $message
            ]);
        }
    }
    // $lobby = Lobby::findOrFail($id);
    $lobby = Lobby::where("id", $id)
        ->where("archive", 0)
        ->firstOrFail();

    $state = null;

    $all_questions = Subjects::with(['subjectsQuestions'])
        ->where('id', $subject_id)
        ->firstOrFail();
    $questions = Subjects::with(['subjectsQuestions' => function ($query) use ($lobby) {
        $query->where('difficulty', $lobby->current_level);
    }])
        ->where('id', $subject_id)
        ->firstOrFail();

    $current_question_index = $lobby->question_num - 1; // assuming 1-based index in DB

    $current_question = $questions->subjectsQuestions[0] ?? null;

    // dd($current_question);
    $items = count($all_questions->subjectsQuestions);


    $itemNumber = $lobby->question_num;
    if ($lobby->started == 0) {

        $subject = Subjects::findOrFail($subject_id);
        return redirect()->route('lobby', [
            'id' => $id,
            'subject_id' => $subject_id,
            'subject' => $subject,
            'team_id' => $team_id

        ]);
    } else {
        if ($team_id != 'organizer') {
            Participants::where('id', $team_id)->update([
                'archive' => 1
            ]);
        }
    }
    if ($lobby->reveal_options == 1) {
        $state = "options-revealed";
    }
    if ($lobby->start_timer == 1) {
        $state = "timer-started";
    }
    if ($lobby->reveal_answer == 1) {
        $state = "answer-revealed";
    }
    if ($lobby->reveal_leaderboard == 1) {
        $state = "leaderboard-revealed";
    }
    if ($lobby->finished == 1) {
        $state = "finished";
    }


    if (Auth::user()) { // ONLY LOGGED IN USER OR ORGANIZER
        broadcast(new QuizEvent($state, $current_question, $itemNumber, $id, $lobby->current_level));
    }

    return Inertia::render(
        'Questionnaire',
        [
            'id' => $id,
            "team_id" => $team_id,
            'subject_id' => $subject_id,
            'quiz_state' => $state,
            'current_question' => $current_question,
            'options_revealed' => $lobby->reveal_options,
            'items' =>  $items,
            'item_number' =>  $itemNumber,
            'current_level' => $lobby->current_level,
            'levels_finished' => $lobby->levels_finished

        ]
    );
})->name('questionnaire');

Route::get('/lobbies', [LobbyController::class, 'getLobby'])->name('lobbies');
Route::get('/lobby-start/{id}', [LobbyController::class, 'start'])->name('lobby-start');
Route::get('/lobby-revealOptions/{id}/{subject_id}', [LobbyController::class, 'revealOptions'])->name('lobby-revealOptions');
Route::get('/lobby-startTimer/{id}/{subject_id}', [LobbyController::class, 'startTimer'])->name('lobby-startTimer');
Route::get('/showOverAllLeaderBoard/{id}/{subject_id}', [LobbyController::class, 'showOverAllLeaderBoard'])->name('showOverAllLeaderBoard');
Route::get('/lobby-gameLevel/{id}/{level}/{subject_id}', [LobbyController::class, 'gameLevel'])->name('lobby-gameLevel');
Route::get('/lobby-changeState/{id}/{level}/{subject_id}', [LobbyController::class, 'changeState'])->name('lobby-changeState');
Route::get('/getLevel/{id}', [LobbyController::class, 'getNewLevel'])->name('getLevel');

Route::get('/lobby-revealAnswer/{id}/{subject_id}', [LobbyController::class, 'revealAnswer'])->name('lobby-revealAnswer');
Route::get('/lobby-nextquestion/{id}/{subject_id}', [LobbyController::class, 'nextquestion'])->name('lobby-nextquestion');
Route::get('/lobby-revealLeaderboard/{id}/{subject_id}/{item_number}', [LobbyController::class, 'revealLeaderboard'])->name('lobby-revealLeaderboard');
Route::post('/lobby', [LobbyController::class, 'store'])->name('lobby.store');
Route::post('/lobby/quick-create', [LobbyController::class, 'quickCreate'])->name('lobby.quick-create')->middleware('auth');
Route::post('/lobby/{id}', [LobbyController::class, 'update'])->name('lobby.update');
Route::post('/lobby/{id}/delete', [LobbyController::class, 'destroy'])->name('lobby.destroy');

Route::post('/close-event/{id}/{subject_id}', [QuizEventController::class, 'closeEvent'])->name('close-event');
Route::get('/clear-prev-data/{id}/{subject_id}', [QuizEventController::class, 'clearPrevData'])->name('clear-prev-data');


Route::get('/subject', function () {
    if (Auth::check()) {
        // Redirect to organizer lobby where subjects are managed
        return redirect()->route('organizerLobby');
    }
    return redirect()->route('login');
})->name('subject.index');

Route::post('/subject', [SubjectController::class, 'store'])->name('subject.store');

Route::get('/teams/{id}/{subject_id}', [ParticipantController::class, 'teams'])->name('teams');
Route::get('/check-lobby-code/{code}', [LobbyController::class, 'checkCode'])->name('check-lobby-code');

Route::get('/organizer-lobbies', [LobbyController::class, 'getOrganizerLobby'])->name('organizer-lobbies');
Route::get('/lobby-status/{id}', [LobbyController::class, 'lobbyStatus'])->name('lobbyStatus');
Route::post('/add-subject-quiz', [SubjectQuestionController::class, 'store'])->name('add-subject-quiz');
Route::get('/getLobbyQuestion/{lobby_id}/{subject_id}', [SubjectQuestionController::class, 'getLobbyQuestion'])->name('getLobbyQuestion');

// Tie Breaker Routes
Route::get('/tie-breaker/check/{lobby_id}/{subject_id}', [TieBreakerController::class, 'checkForTies'])->name('tie-breaker.check');
Route::post('/tie-breaker/start/{lobby_id}/{subject_id}', [TieBreakerController::class, 'startTieBreaker'])->name('tie-breaker.start');
Route::get('/tie-breaker/question/{lobby_id}/{subject_id}', [TieBreakerController::class, 'getCurrentTieBreakerQuestion'])->name('tie-breaker.question');
Route::post('/tie-breaker/answer/{lobby_id}/{subject_id}', [TieBreakerController::class, 'processTieBreakerAnswer'])->name('tie-breaker.answer');
Route::post('/tie-breaker/next-round/{lobby_id}/{subject_id}', [TieBreakerController::class, 'nextTieBreakerRound'])->name('tie-breaker.next-round');
Route::get('/updateScore/{id}/{score}/{ans}/{question}/{lobby_id}/{question_id}/{q_type}/{prev_score}/{new_question}', [ParticipantController::class, 'updateScore'])->name('updateScore');
Route::get('/leaderboard/{id}/{subject_id}', [ParticipantController::class, 'leaderboard'])->name('leaderboard');
Route::get('/currentQuestionLeaderboard/{id}/{question_id}', [ParticipantController::class, 'currentQuestionLeaderboard'])->name('currentQuestionLeaderboard');
Route::get('/participant-code-update/{id}/{code}', [ParticipantController::class, 'updateTeamCode'])->name('participant-code-update');
Route::get('/participant-shor-answer/{id}/{subject_id}', [ParticipantController::class, 'shortAnswer'])->name('participant-shor-answer');
Route::post('/participant-answer-update', [ParticipantController::class, 'updateAns'])->name('participant-shor-answer');

Route::get('/report/teams/excel/{lobby_id}/{subject_id}', [ReportController::class, 'downloadTeamsReport']);
Route::get('/report/lobby-management/{lobby_id?}', [ReportController::class, 'downloadLobbyManagementReport'])->name('report.lobby-management');
Route::get('/report/quiz-management/{lobby_id?}', [ReportController::class, 'downloadQuizManagementReport'])->name('report.quiz-management');

Route::post('/login-info', [LoginLogsController::class, 'isFirstLogin'])->name('login-info');

Route::prefix('api/live-quizzes/{quiz}')->middleware('auth')->group(function () {
    Route::get('session', [LiveQuizSessionController::class, 'getSessionState']);

    Route::post('create-session', [LiveQuizSessionController::class, 'createSession']);

    Route::post('start-quiz', [LiveQuizSessionController::class, 'startQuiz']);
    Route::post('next-question', [LiveQuizSessionController::class, 'nextQuestion']);
    Route::post('reveal-answer', [LiveQuizSessionController::class, 'revealAnswer']);
    Route::post('end-quiz', [LiveQuizSessionController::class, 'endQuiz']);
    Route::post('join-participant', [LiveQuizSessionController::class, 'joinParticipant']);
    Route::post('submit-answer', [LiveQuizSessionController::class, 'submitAnswer']);
    Route::get('participants', [LiveQuizSessionController::class, 'getParticipants']);
});
