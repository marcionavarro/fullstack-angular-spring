import { Component, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { Hello } from './hello/hello';
import { BemVindo } from './bem-vindo/bem-vindo';

@Component({
  imports: [Hello, BemVindo],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  nome: string = 'João';
}
