package org.tasks.gtasks

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint
import org.tasks.R
import org.tasks.themes.TasksSettingsTheme
import org.tasks.themes.Theme
import javax.inject.Inject

@AndroidEntryPoint
class GoogleTasksSignInActivity : ComponentActivity() {
    @Inject lateinit var theme: Theme

    private val viewModel: GoogleTasksSignInViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            TasksSettingsTheme(
                theme = theme.themeBase.index,
                primary = theme.themeColor.primaryColor,
            ) {
                LaunchedEffect(Unit) {
                    viewModel.start { url ->
                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                    }
                }
                LaunchedEffect(viewModel.complete) {
                    if (viewModel.complete) {
                        setResult(Activity.RESULT_OK)
                        finish()
                    }
                }
                val error = viewModel.error
                if (error != null) {
                    AlertDialog(
                        onDismissRequest = {},
                        title = { Text(stringResource(R.string.google_tasks_sign_in_failed)) },
                        text = { Text(error) },
                        confirmButton = {
                            TextButton(onClick = {
                                setResult(
                                    Activity.RESULT_CANCELED,
                                    Intent().putExtra(EXTRA_ERROR, error)
                                )
                                finish()
                            }) {
                                Text(stringResource(R.string.ok))
                            }
                        },
                    )
                } else {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        CircularProgressIndicator()
                        Text(
                            text = stringResource(R.string.gtasks_GLA_authenticating),
                            modifier = Modifier.padding(top = 16.dp),
                        )
                    }
                }
            }
        }
    }

    companion object {
        const val EXTRA_ERROR = "extra_error"
    }
}
