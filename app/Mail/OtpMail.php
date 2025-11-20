<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class OtpMail extends Mailable
{
    use Queueable, SerializesModels;
    public string $name;
    public string $subject_line;
    public string $email;
    public string $body;
    /**
     * Create a new message instance.
     */
    public function __construct($name, $email, $subject, $body)
    {
        //
        $this->name = $name;
        $this->email = $email;
        $this->body = $body;
        $this->subject_line = $subject;
    }

    /**
     * Get the message envelope.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: $this->subject_line,
        );
    }

    /**
     * Get the message content definition.
     */
    // public function content(): Content
    // {
    //     return new Content(
    //         view: 'view.otp',
    //     );
    // }

    public function build()
    {
        $logoCid = null;
        $logoPath = public_path('images/LOGO.png');

        if (file_exists($logoPath)) {
            $logoCid = $this->embed($logoPath);
        }

        return $this->subject($this->subject_line)
            ->view('emails.otp')
            ->with([
                'name' => $this->name,
                'email' => $this->email,
                'body' => $this->body,
                'logoCid' => $logoCid,
            ]);
    }
    /**
     * Get the attachments for the message.
     *
     * @return array<int, \Illuminate\Mail\Mailables\Attachment>
     */
    public function attachments(): array
    {
        return [];
    }
}
