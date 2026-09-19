import { NgStyle, NgClass } from '@angular/common';
import { Component, Input, input } from '@angular/core';

@Component({
  imports: [NgStyle, NgClass],
  selector: 'app-funcionario-card',
  // styleUrl: './funcionario-card.css',
  templateUrl: './funcionario-card.html',
  styles: [
    `
      .card-body {
        text-transform: uppercase;
        color: blue;
      }
    `,
  ],
})
export class FuncionarioCard {
  @Input() funcionario!: { id: number; nome: string };

  getEstilosCartao() {
    return {
      'border-width.px': this.funcionario.id,
      backgroundColor: this.funcionario.id % 2 == 0 ? 'lightblue' : 'lightgreen',
    };
  }

  isAdmin() {
    return this.funcionario.nome.startsWith('M');
  }
}
