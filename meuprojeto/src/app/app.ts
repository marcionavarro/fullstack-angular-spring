import { Component, EventEmitter, NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { FuncionarioCard } from './funcionario-card/funcionario-card';
import { FuncionarioForm } from './funcionario-form/funcionario-form';

@Component({
  imports: [FormsModule, FuncionarioCard, FuncionarioForm],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  funcionarios: { id: number; nome: string }[] = [];

  aoAdicionar(funcionario: { id: number; nome: string }) {
    this.funcionarios.push(funcionario);
  }
}
