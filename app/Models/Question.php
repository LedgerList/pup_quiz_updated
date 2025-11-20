<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Question extends Model
{
    use HasFactory;
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'quiz_id',
        'type',
        'question_text',
        'image_path',
        'time_limit',
        'points',
        'true_false_answer',
        'short_answer',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'true_false_answer' => 'boolean',
    ];

    /**
     * Get the quiz that owns the question.
     */
    public function quiz(): BelongsTo
    {
        return $this->belongsTo(Quiz::class);
    }

    /**
     * Get the options for the question (if it's a multiple-choice question).
     */
    public function options(): HasMany
    {
        return $this->hasMany(Option::class);
    }
    public function points_history(): HasMany
    {
        return $this->hasMany(PointsHistory::class);
    }
 
}
