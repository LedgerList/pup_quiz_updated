<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Lobby extends Model
{
    //
    protected $table = 'lobby';

    protected $fillable = [
        'name',
        'start_date',
        'lobby_code',
        'user_id',
        'tie_breaker_active',
        'tie_breaker_round',
        'tie_breaker_question_num'
    ];

    public function subjects()
    {
        return $this->hasMany(Subjects::class);
    }

    public function lobbyMngnt()
    {
        return $this->hasMany(LoobyManagement::class);
    }
    
    public function pre_registration_log()
    {
        return $this->hasMany(PreRegistration::class);
    }

    /**
     * Get all participants for this lobby (via lobby_code)
     */
    public function participants()
    {
        return $this->hasMany(Participants::class, 'lobby_code', 'lobby_code');
    }

    /**
     * Get all points history records for this lobby
     */
    public function pointsHistory()
    {
        return $this->hasMany(PointsHistory::class, 'lobby_id');
    }
}
