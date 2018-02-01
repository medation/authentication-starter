import {Component} from '@angular/core';
import {NavController, LoadingController, ToastController} from 'ionic-angular';
import {SignupPage} from "../signup/signup";
import { AuthenticationService } from './../../services/authentication';
import {finalize} from 'rxjs/operators/finalize';

@Component({
  selector: 'page-login',
  templateUrl: 'login.html'
})
export class LoginPage {

  constructor(private navCtrl: NavController,
              private loadingCtrl: LoadingController,
              private authenticationService: AuthenticationService,
              private toastCtrl: ToastController) {
  }

  signup() {
    this.navCtrl.push(SignupPage);
  }

  login(value: any) {
    let loading = this.loadingCtrl.create({
      spinner: 'bubbles',
      content: 'Logging in ...'
    });

    loading.present();

    this.authenticationService
      .login(value)
      .pipe(finalize(() => loading.dismiss()))
      .subscribe(
        () => {},
        err => this.handleError(err));
  }

  handleError(error: any) {
    let message: string;
    if (error.status && error.status === 401) {
      message = 'Login failed';
    }
    else {
      message = `Unexpected error: ${error.statusText}`;
    }

    const toast = this.toastCtrl.create({
      message,
      duration: 5000,
      position: 'bottom'
    });

    toast.present();
  }

}
