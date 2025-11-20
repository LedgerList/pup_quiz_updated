<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('participants', function (Blueprint $table) {
            // Add unique composite index to prevent duplicate registrations per lobby/subject
            // A participant can register for different lobbies/subjects, but not duplicate within the same lobby/subject
            $table->unique(['lobby_code', 'subject_id', 'team_leader_email'], 'unique_participant_email_per_lobby_subject');
            $table->unique(['lobby_code', 'subject_id', 'student_number'], 'unique_participant_student_per_lobby_subject');
            
            // Add index for better query performance
            $table->index(['lobby_code', 'subject_id'], 'idx_lobby_subject');
            $table->index('subject_id', 'idx_subject_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('participants', function (Blueprint $table) {
            // Drop unique indexes
            $table->dropUnique('unique_participant_email_per_lobby_subject');
            $table->dropUnique('unique_participant_student_per_lobby_subject');
            
            // Drop performance indexes
            $table->dropIndex('idx_lobby_subject');
            $table->dropIndex('idx_subject_id');
        });
    }
};
