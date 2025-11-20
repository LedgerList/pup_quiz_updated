<?php

namespace App\Http\Controllers;

use App\Exports\TeamsExport;
use App\Exports\LobbyManagementExport;
use App\Exports\QuizManagementExport;
use Maatwebsite\Excel\Facades\Excel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ReportController extends Controller
{
    public function downloadTeamsReport($lobby_id,$subjecId)
    {
        try {
            $fileName = 'teams_report_' . now()->format('Ymd_His') . '.xlsx';
            return Excel::download(new TeamsExport($lobby_id,$subjecId), $fileName);
        } catch (\Exception $e) {
            \Log::error('Error generating teams report: ' . $e->getMessage());
            return response()->json([
                'error' => 'Failed to generate report. Please try again.',
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function downloadLobbyManagementReport($lobbyId = null)
    {
        $userId = Auth::id();
        $fileName = 'lobby_management_logs_' . now()->format('Ymd_His') . '.xlsx';
        return Excel::download(new LobbyManagementExport($userId, $lobbyId), $fileName);
    }

    public function downloadQuizManagementReport($lobbyId = null)
    {
        $userId = Auth::id();
        $fileName = 'quiz_management_logs_' . now()->format('Ymd_His') . '.xlsx';
        return Excel::download(new QuizManagementExport($userId, $lobbyId), $fileName);
    }
}