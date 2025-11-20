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
        Schema::table('lobby', function (Blueprint $table) {
            $table->boolean('tie_breaker_active')->default(false)->after('levels_finished');
            $table->enum('tie_breaker_round', ['easy', 'average', 'hard'])->nullable()->after('tie_breaker_active');
            $table->integer('tie_breaker_question_num')->default(0)->after('tie_breaker_round');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('lobby', function (Blueprint $table) {
            $table->dropColumn(['tie_breaker_active', 'tie_breaker_round', 'tie_breaker_question_num']);
        });
    }
};
