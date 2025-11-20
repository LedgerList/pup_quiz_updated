<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Participants extends Model
{
    //

    protected $fillable = [
        'team',
        'members',
        'score',
        'archive',
        'lobby_code',
        'prev_answer',
        'prev_answer_correct',
        "team_leader",
        "team_leader_email",
        "is_online",
        "student_number",
        "course_year",
        "contact_number",
        "student_id",
        "consent_form",
        "registration_form",
        "subject_id",
        "invitation_accepted",
        "invitation_accepted_at"
    ];

    /**
     * The attributes that should be hidden for serialization.
     * These fields will not be included in JSON responses by default.
     */
    protected $hidden = [
        'team_leader_email',
        'student_number',
        'contact_number',
        'student_id',
        'consent_form',
        'registration_form',
        'members', // Contains sensitive member information
    ];

    /**
     * Get the subject that this participant belongs to
     */
    public function subject(): BelongsTo
    {
        return $this->belongsTo(Subjects::class, 'subject_id');
    }

    /**
     * Get the lobby that this participant belongs to (via lobby_code)
     */
    public function lobby(): BelongsTo
    {
        return $this->belongsTo(Lobby::class, 'lobby_code', 'lobby_code');
    }

    /**
     * Get all points history records for this participant
     */
    public function pointsHistory(): HasMany
    {
        return $this->hasMany(PointsHistory::class, 'participant_id');
    }

    /**
     * Get leaderboard logs for this participant
     */
    public function logs(): HasMany
    {
        return $this->hasMany(LeaderboardLog::class, 'participant_id', 'id');
    }

    /**
     * Get pre-registration records for this participant
     */
    public function pre_registration(): HasMany
    {
        return $this->hasMany(PreRegistration::class, 'participant_id', 'id');
    }
}
