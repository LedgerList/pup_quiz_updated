<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class LiveParticipant extends Model
{
    use HasFactory;

    protected $fillable = [
        'live_session_id',
        'user_id',
        'score',
        'last_answer_time',
        'answers'
    ];

    protected $casts = [
        'score' => 'integer',
        'last_answer_time' => 'datetime',
        'answers' => 'array', 
    ];

    public function liveSession(): BelongsTo
    {
        return $this->belongsTo(LiveSession::class);
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}