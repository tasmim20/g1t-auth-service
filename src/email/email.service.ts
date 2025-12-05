// /* eslint-disable @typescript-eslint/no-unsafe-call */
// import * as nodemailer from 'nodemailer';
// import { Injectable, InternalServerErrorException } from '@nestjs/common';
// import { RpcException } from '@nestjs/microservices';

// @Injectable()
// export class EmailService {
//   private transporter: nodemailer.Transporter;

//   constructor() {
//     this.transporter = nodemailer.createTransport({
//       host: process.env.SMTP_HOST,
//       port: Number(process.env.SMTP_PORT),
//       secure: false,
//       auth: {
//         user: process.env.SMTP_USER,
//         pass: process.env.SMTP_PASS,
//       },
//     });
//   }

//   async sendConfirmationEmail(to: string, token: string) {
//     try {
//       const url = `http://localhost:5000/auth/confirm?token=${token}`;
//       await this.transporter.sendMail({
//         from: `"Green1Taxi" <${process.env.SMTP_USER}>`,
//         to,
//         subject: 'Confirm your email',
//         html: `<p>Please click this link to confirm your email:</p>
//                <a href="${url}">${url}</a>`,
//       });
//       console.log('✅ Confirmation email sent to', to);
//     } catch (error) {
//       console.error('Email Send Error:', error);
//       throw new InternalServerErrorException(
//         'Failed to send confirmation email.',
//       );
//     }
//   }
//   async sendOTPEmail(to: string, otp: string) {
//     try {
//       await this.transporter.sendMail({
//         from: `"Green1Taxi" <${process.env.EMAIL_USER}>`,
//         to,
//         subject: 'Your OTP for Password Reset',
//         html: `<p>Your OTP is: <b>${otp}</b></p>
//              <p>It is valid for 10 minutes.</p>`,
//       });
//     } catch (error) {
//       console.error('OTP Email Error:', error);
//       throw new RpcException('Failed to send OTP email.');
//     }
//   }
// }
