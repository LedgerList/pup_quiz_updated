<?php

namespace App\Http\Controllers;

use App\Models\Lobby;
use App\Models\Subjects;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Inertia\Inertia;
use PhpParser\Node\Stmt\TryCatch;

class SubjectController extends Controller
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
    public function store(Request $request)
    {
        //
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',

        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors(),
            ], 422);
        }

        // Subjects::create([
        //     'subject_name' => $request->input('name'),
        //     'lobby_id' => $request->input('id'),
        //     'quiz_title' => ''
        //     // 'user_id' => Auth::user()->id
        // ]);

        $date = $request->input('date'); // e.g. "2025-11-19 21:40:00" or empty string for first subject

        // Convert to proper format for MySQL
        // If date is empty (first subject creation), use current date/time
        // Parse the date string and ensure it's treated as local time (Asia/Manila timezone)
        if (!empty($date)) {
            // The date string is in 'Y-m-d H:i:s' format from frontend
            // Parse it and set timezone to Asia/Manila to preserve the intended time
            $startDate = Carbon::parse($date, config('app.timezone'))
                ->setTimezone(config('app.timezone'))
                ->format('Y-m-d H:i:s');
        } else {
            $startDate = now(config('app.timezone'))->format('Y-m-d H:i:s');
        }
        try {
            Subjects::create([
                'subject_name' => $request->input('name'),
                'lobby_id' => $request->input('id'),
                'start_date' => $startDate,
                'quiz_title' => ''
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
        $lobbies = Lobby::with('subjects')
            ->where('id',  $request->input('id'))
            ->get();

        return Inertia::render('LobbyCategory', [
            'lobbies' => $lobbies,
            'id' => $request->input('id'),
        ]);
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
