import { Component, signal } from '@angular/core';
import { TabsModule } from 'primeng/tabs';

@Component({
  imports: [TabsModule],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  protected readonly title = signal('algamoney-ui');
}
