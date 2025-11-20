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
        Schema::create('questions', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('quiz_id');
            $table->enum('type', ['multiple-choice', 'true-false', 'short-answer']);
            $table->text('question_text');
            $table->string('image_path')->nullable();
            $table->integer('time_limit')->nullable();
            $table->integer('points')->nullable();
            $table->enum('difficulty', ['easy', 'average', 'hard'])->default('easy');
            $table->boolean('true_false_answer')->nullable();
            $table->text('short_answer')->nullable();
            $table->timestamps();
            
            $table->foreign('quiz_id')->references('id')->on('quizzes')->onDelete('cascade');
            $table->index('quiz_id');
            $table->index('type');
            $table->index('difficulty');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('questions');
    }
};
