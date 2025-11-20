<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use App\Models\User;

class SessionLogs extends Model
{
    use HasFactory;
    //

    protected $table = 'session_logs';
    protected $fillable = [
        'user_id',
        'logout_timestamp',
        'ip_address',

    ];

    public function user()
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }
}
