import { Component, EventEmitter, Output } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
  imports: [FormsModule],
  selector: 'app-funcionario-form',
  styleUrl: './funcionario-form.css',
  templateUrl: './funcionario-form.html',
})
export class FuncionarioForm {
  ultimoId = 0;
  nome = 'Marcio';
  adicionado = false;
  @Output() funcionarioAdicionado = new EventEmitter();

  adicionar() {
    console.log(`Adicionado ${this.nome}`);
    this.adicionado = true;

    const funcionario = {
      id: ++this.ultimoId,
      nome: this.nome,
    };

    this.funcionarioAdicionado.emit(funcionario);
  }
}
