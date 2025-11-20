<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class LiveSession extends Model
{
    use HasFactory;
    protected $fillable = [
        'quiz_id',
        'current_question_index',
        'show_answer',
        'status',
        'session_host_id',
    ];

    protected $casts = [
        'show_answer' => 'boolean',
        'current_question_index' => 'integer',
    ];

    public function quiz(): BelongsTo
    {
        return $this->belongsTo(Quiz::class);
    }

    public function host(): BelongsTo
    {
        return $this->belongsTo(User::class, 'session_host_id');
    }

    public function participants(): HasMany
    {
        return $this->hasMany(LiveParticipant::class);
    }
}