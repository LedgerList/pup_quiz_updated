<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PointsHistory extends Model
{
    //
    protected $table = 'points_history';
    protected $fillable = [
        'points',
        'question',
        'answer',
        'participant_id',
        'lobby_id',
        'question_id',
        'attempt_answers'
    ];

    /**
     * Get the participant that owns this points history record
     */
    public function participant(): BelongsTo
    {
        return $this->belongsTo(Participants::class, 'participant_id');
    }

    /**
     * Get the lobby that this points history belongs to
     */
    public function lobby(): BelongsTo
    {
        return $this->belongsTo(Lobby::class, 'lobby_id');
    }

    /**
     * Get the question that this points history belongs to
     */
    public function subjectQuestion(): BelongsTo
    {
        return $this->belongsTo(SubjectQuestion::class, 'question_id');
    }

    /**
     * Legacy method for backward compatibility
     * @deprecated Use subjectQuestion() instead
     */
    public function question(): BelongsTo
    {
        return $this->subjectQuestion();
    }
}
